# Golang-ShortUrlServer
# 短網址服務的練習

## 練習以Golang 搭配Gin框架建立一個後端伺服器，並使用Quasar 建立前端的輸入畫面取得處理過後的短網址。
整個網站建置於 AWS EC2上透過 Nginx 代理前端與後端，並使用supervisor監聽golang運行狀況，
再將資料儲存於 AWS dynamoDB，原本還想順便處理網域與https，但基於預算考量暫時放棄。


