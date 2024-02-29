# Golang-ShortUrlServer

## 練習以Golang 搭配Gin框架建立一個後端伺服器，並使用Quasar 建立前端的輸入畫面取得處理過後的短網址。
整個網站建置於 AWS EC2上透過 Nginx 代理前端與後端，並使用supervisor監聽golang運行狀況，
再將資料儲存於 AWS dynamoDB。
後續為了讓整體看起來更完整一些，使用Aws Route53購買了最便宜的網域，以及加上SSL憑證。

## 2024/02/22
目前增加了以下功能：
* 建立登入者 (查找DynamoDB來判斷帳號是否重複，沒有重複則透過bcrypt對密碼編碼後存入資料庫)
* 增加登入功能 (查找DynamoDB帳號，取出編碼後的密碼進行比對，符合的則產生JWT Token回傳)
* 登入後便可以查詢該帳號過往的紀錄 (針對DynamoDB資料表建立全域補助索引，查找登入者帳號，撈出符合的項目)
