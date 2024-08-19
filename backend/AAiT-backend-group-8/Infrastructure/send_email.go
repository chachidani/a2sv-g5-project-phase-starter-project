package infrastructure

import (
    "fmt"
    "gopkg.in/gomail.v2"
)

func SendVerificationEmail(to, token string) error {
    m := gomail.NewMessage()
    m.SetHeader("From", "BLOGSAPI@gmail.com") 
    m.SetHeader("To", to)
    m.SetHeader("Subject", "Verify your email")
    m.SetBody("text/plain", fmt.Sprintf("Click here to verify your email: http://localhost:8080/verify?token=%s", token))

    d := gomail.NewDialer(
        "smtp.gmail.com",  
        587,              
        "jovaniasfaw@gmail.com",   
        "bjqj bqpw llsd rzsv",            
    )

    return d.DialAndSend(m)
}
