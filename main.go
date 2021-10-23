package main

import (
	"fmt"
	"github.com/gocolly/colly"
)

func main() {
	// 创建collector
	c := colly.NewCollector()

	// 事件监听，通过callback执行事件处理
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		fmt.Printf("Link found: %q -> %s\n", e.Text, link)
		c.Visit(e.Request.AbsoluteURL(link))

	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})
	c.Visit("http://go-colly.org/")

}
