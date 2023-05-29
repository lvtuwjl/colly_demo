package main

import (
	"encoding/csv"
	"errors"
	"fmt"
	"github.com/gocolly/colly/v2"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 并发任务处理
// var done chan struct{}
var ch chan string
var yearCVEMap map[string]int32
var mu sync.Mutex

const YearLimit = 2000
const CVEPATH = "CVE"
const MappingFile = "mapping.csv" // cveId 年份映射表

func main() {
	//done = make(chan struct{})
	ch = make(chan string, 100)
	yearCVEMap = make(map[string]int32)
	// 1.生成CVE文件夹
	err := os.Mkdir(CVEPATH, 0750)
	if err != nil {
		log.Fatal("CVE文件夹创建失败")
	}

	// 2.创建映射文件
	mappingFile, err := os.OpenFile(MappingFile, os.O_CREATE|os.O_RDWR, 0660)
	if err != nil {
		log.Fatal("create mapping.csv failed:", err)
	}
	_, err = mappingFile.Write([]byte{0xef, 0xbb, 0xbf}) // BOM头文件
	if err != nil {
		log.Fatal("write BOM failed:", err)
	}
	defer mappingFile.Close()
	mapWriter := csv.NewWriter(mappingFile)

	row := []string{"CVE编号", "名称", "分数"}
	err = mapWriter.Write(row)
	if err != nil {
		log.Fatalf("can not write title to mapping file, err is %+v", err)
	}
	mapWriter.Flush()
	// 读取csv文件 爬取数据
	go readCSV("mapping_all.csv", mapWriter)
	//go func() {
	for {
		select {
		case cveId, ok := <-ch:
			//time.Sleep(time.Second * 3)
			if !ok {
				//done <- struct{}{}
				time.Sleep(time.Second * 10)
				fmt.Println("Finish!!!")
				return
			}
			//go func() {
			year := strings.Split(cveId, "-")[1]
			writeCVE(cveId, mapWriter, year, yearCVEMap)
			//}()
		}
	}
	//cveId := <-ch
	//year := strings.Split(cveId, "-")[1]
	//writeCVE(cveId, mapWriter, year, yearCVEMap)
	//}()

	//<-done

	//time.Sleep(time.Hour * 100)
}

func readCSV(path string, mappingFile *csv.Writer) {
	defer close(ch)
	file, err := os.Open(path)
	if err != nil {
		log.Fatal("open file failed, err=", err)
	}
	defer file.Close()
	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	count := 0
	//yearCVEMap := make(map[string]int32) // 每年对应CVE数量
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}
		// do something with read line
		fmt.Printf("%+v\n", rec)
		if len(rec) == 0 || !strings.Contains(rec[0], "CVE") {
			fmt.Println("第一个元素不符合要求", rec)
			continue
		}

		if !strings.Contains(rec[0], "-") {
			fmt.Println("第一个元素不符合要求", rec)
			continue
		}

		list := strings.Split(rec[0], "-")
		if year, err := strconv.Atoi(list[1]); err != nil || year < 2018 {
			fmt.Println("年份太低或执行出错", year, err)
			continue
		}

		year := strings.Split(rec[0], "-")[1]
		mu.Lock()
		c := yearCVEMap[year]
		mu.Unlock()
		if c >= YearLimit {
			fmt.Println("year limit:", year)
			continue
		}
		count++
		//if n > 10 {
		//	fmt.Println("csv count:", n)
		//	break
		//}
		//writeCVE(rec[0], mappingFile, year, yearCVEMap)
		ch <- strings.TrimSpace(rec[0])
	}
	fmt.Println("finish csv count:", count)
}

func writeCVE(cveId string, mappingFile *csv.Writer, year string, ym map[string]int32) {
	//cveId := "CVE-2022-47460"
	score, err := getCVEScore(cveId)
	if err != nil {
		log.Println("get cve score err:", err)
		return
	}
	// 根据分数来判断
	if score < 4.0 {
		fmt.Println("score太低，舍弃，score:", score)
		return
	}

	cveUrl, err := getUrlBynsfocus(cveId)
	if err != nil {
		log.Println("get cve info err:", err)
		return
	}

	cveText, err := getCVEBynsfocus(cveUrl)
	if err != nil {
		log.Println("get cve cveText err:", err)
		return
	}

	//score, _ := getCVEScore(cveId)
	vcss, err := getCVECVSS(cveId)
	if err != nil {
		log.Println("get cve vcss err:", err)
		return
	}

	// 根据分数来判断
	if vcss.vector != "Network" && vcss.vector != "Adjacent Network" {
		fmt.Println("vector not Network，vector:", vcss.vector)
		return
	}

	suggestion, err := getCVESuggestion(cveText)
	if err != nil {
		log.Println("get cve suggestion err:", err)
		return
	}

	exp, remedia, err := getCVEExp(cveId, suggestion)
	if err != nil {
		log.Println("get cve exp and remedia err:", err)
		return
	}

	//if exp == "" {
	//	fmt.Println("empty exp:", exp)
	//	return
	//}

	name, err := getCVEName(cveText)
	if err != nil {
		log.Println("get cve name err:", err)
		return
	}
	cveDesc, err := getCVEDesc(cveText)
	if err != nil {
		log.Println("get cve cveDesc err:", err)
		return
	}
	publishTime, err := getCVEPublishTime(cveText)
	if err != nil {
		log.Println("get cve publishTime err:", err)
		return
	}

	id, err := getCWEId(cveId)
	if err != nil {
		log.Println("get cve id err:", err)
		return
	}

	referUrls, err := getCVEReferURL(cveId)
	if err != nil {
		log.Println("get cve referUrls err:", err)
		return
	}

	// 参考链接 可能有多个
	referStrs := ""
	if len(referUrls) == 0 {
		referStrs = "{'type': 'url', 'ref': ''}"
	}
	for k, url := range referUrls {
		// 最多保留5个引用链接
		if k == 5 {
			break
		}
		referStrs += fmt.Sprintf("{'type': 'url', 'ref': '%s'},\n", url)
		referStrs += "        "
	}

	version, err := getCVEAffectedVersion(cveText)
	if err != nil {
		log.Println("get cve version err:", err)
		return
	}

	desc := fmt.Sprintf(text, name, cveDesc, publishTime, cveId, id, referStrs, score, vcss.vector, vcss.complexity,
		vcss.privilege, vcss.scope, exp, remedia, vcss.confidentiality, vcss.integrity, vcss.harmness, version, suggestion)
	fmt.Println(desc)

	// 3.创建子CVE文件夹
	subCVEName := strings.ToLower(strings.ReplaceAll(cveId, "-", "_"))
	subCVEDir := CVEPATH + "/" + subCVEName
	err = os.Mkdir(subCVEDir, 0750)
	if err != nil {
		log.Fatal("子CVE文件夹创建失败")
	}

	// 4.创建codes文件夹
	codesDir := subCVEDir + "/" + "codes"
	err = os.Mkdir(codesDir, 0750)
	if err != nil {
		log.Fatal("创建codes文件夹失败")
	}
	// 写入meta.go
	{
		metaFile, err := os.OpenFile(codesDir+"/meta.go", os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			log.Fatal("open meta.go failed:", err)
		}
		defer metaFile.Close()

		metaFile.WriteString(`package main

import "fmt"

func main() {
	fmt.Println(`)
		metaFile.WriteString("`")
		n, err := metaFile.WriteString(desc)
		if err != nil {
			log.Fatal("write meta.go failed:", err)
		}
		metaFile.WriteString("`")
		metaFile.WriteString(`)
}`)

		fmt.Println("write meta.go success,n=", n)
	}
	// 写入check.py
	{
		checkFile, err := os.OpenFile(codesDir+"/check.py", os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			log.Fatal("open check.py failed:", err)
		}
		defer checkFile.Close()

		n, err := checkFile.WriteString(`#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# standard modules
from metasploit import module
import os

# extra modules
dependencies_missing = False
try:
    import requests
    import logging
except ImportError:
    dependencies_missing = True


temp_dir = os.path.dirname(__file__)
strmetaout = os.popen(temp_dir+"/meta", "r", 1).read()
metadata = eval(strmetaout)

def vulscan(args):

    path = f'{temp_dir}/vulscan --ip={args["rhosts"]} --port={args["rport"]} --od={args["otherdata"]}'
    #path = f'{temp_dir}/vulscan --ip={args["rhosts"]} --port={args["rport"]}'
    argsvarout = os.popen(path).read()
    argsvarout = argsvarout.replace('\n', '')
    argsvarout = argsvarout.replace('\r', '')
    # logging.error(argsvarout)
    return argsvarout


def run(args):
    # 自定义模块时，主要的逻辑代码放在此处 ---start

    vulscan(args)
    # 自定义模块时，主要的逻辑代码放在此处 ---end


if __name__ == '__main__':
    # logging.error("go binary executr...33")
    module.run(metadata, run, soft_check=vulscan)`)
		if err != nil {
			log.Fatal("write check.py failed:", err)
		}

		fmt.Println("write check.py success,n=", n)
	}
	// 写入vulscan.go
	{
		vulscanFile, err := os.OpenFile(codesDir+"/vulscan.go", os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			log.Fatal("open vulscan.go failed:", err)
		}
		defer vulscanFile.Close()

		n, err := vulscanFile.WriteString(`package main

import (
	"flag"
	"fmt"
)

var ip string
var port string

var otherdata string

func Init() {
	/*
		go run .\vulscan.go --ip 1.1.1.1 --port 80 --od '{\"is_sec\":false,\"srv_proto\":\"http\"}'
	*/
	flag.StringVar(&ip, "ip", "192.168.183.129", "Need intput ip")
	flag.StringVar(&port, "port", "8181", "Need intput port")
	flag.StringVar(&otherdata, "od", "{\"is_sec\":false,\"srv_proto\":\"\"}", "Need intput otherdata")
}

func main() {
	//logrus.Error("cve-2022-22947:xxxxxxxxxxxxxxxxxxxxxxxxxxx")
	Init()
	flag.Parse()

	fmt.Println("safe")

}
`)
		if err != nil {
			log.Fatal("write vulscan.go failed:", err)
		}

		fmt.Println("write vulscan.go success,n=", n)
	}

	// 5.创建docs文件夹
	docsDir := subCVEDir + "/" + "docs"
	err = os.Mkdir(docsDir, 0750)
	if err != nil {
		log.Fatal("创建docs文件夹失败")
	}
	// 写入README.md
	{
		readmeFile, err := os.OpenFile(docsDir+"/README.md", os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			log.Fatal("open README.md failed:", err)
		}
		defer readmeFile.Close()

		n, err := readmeFile.WriteString(`# CVE-2022-42475

- name:
  - Spring Cloud Gateway spel 远程代码执行
- CVSS: 9.9(Critical)
    - CVSS Version: 3.x
- Type: heap-based buffer overflow vulnerability
- CWE: CWE-122
- Environment:
    - Name: FortiOS SSL-VPN
        - Version: 7.2.0-7.2.2, 7.0.0-7.0.8, 6.4.0-6.4.10, 6.2.0-6.2.11, none-6.0.15
    - Name: FortiProxy SSL-VPN
        - Version: 7.2.0-7.2.1, none-7.0.7
- Description:
    - This vulnerability may allow a remote unauthenticated attacker to execute arbitrary code or commands via specifically crafted requests.
- suggestion:
    -
- Build environment:
  - docker-compose up -d 
`)
		if err != nil {
			log.Fatal("write README.md failed:", err)
		}

		fmt.Println("write README.md success,n=", n)
	}

	// 6.创建test文件夹
	testDir := subCVEDir + "/" + "test"
	err = os.Mkdir(testDir, 0750)
	if err != nil {
		log.Fatal("创建test文件夹失败")
	}

	// 7.写入统计记录表 csv 年份 id score
	{
		//list := strings.Split(cveId, "-")
		score := strconv.FormatFloat(score, 'f', -1, 64)
		row := []string{cveId, name, score}
		err = mappingFile.Write(row)
		if err != nil {
			log.Fatalf("can not write row to mapping file, err is %+v", err)
		}
		mappingFile.Flush()
	}
	mu.Lock()
	ym[year]++
	mu.Unlock()
}

// 绿盟获取具体CVE的URL
func getUrlBynsfocus(cve string) (string, error) {
	if cve == "" {
		return "", errors.New("empty cve")
	}
	var url string
	c := colly.NewCollector()

	// Find and visit all links
	c.OnHTML("ul[class='vul_list'] > li > a", func(e *colly.HTMLElement) {
		url = e.Attr("href")
		fmt.Println("getUrlBynsfocus url:", url)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	//c.Visit("http://www.nsfocus.net/vulndb/79618")
	//err := c.Visit("http://www.nsfocus.net/index.php?os=&type_id=&keyword=CVE-2022-47460&act=sec_bug&submit=+")
	err := c.Visit(fmt.Sprintf("http://www.nsfocus.net/index.php?os=&type_id=&keyword=%s&act=sec_bug&submit=+", cve))
	if err != nil {
		return "", err
	}
	return url, nil
}

// 绿盟获取具体漏洞详情
func getCVEBynsfocus(url string) (string, error) {
	if url == "" {
		return "", errors.New("empty url")
	}
	var detail string
	c := colly.NewCollector()
	c.OnHTML("div[class='vulbar']", func(element *colly.HTMLElement) {
		fmt.Printf("text:%v\n", element.Text)
		detail = element.Text
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	//err := c.Visit("http://www.nsfocus.net/vulndb/79618")
	err := c.Visit("http://www.nsfocus.net" + url)
	if err != nil {
		return "", err
	}
	if detail == "" {
		return "", errors.New("empty detail")
	}
	return detail, nil
}

// 漏洞名称
func getCVEName(text string) (string, error) {
	list := strings.Split(text, "发布日期：")
	names := strings.Split(list[0], "（CVE-")
	return strings.TrimSpace(names[0]), nil
}

// 漏洞描述
func getCVEDesc(text string) (string, error) {
	desc := ""
	all := strings.SplitN(text, "描述：", 2)
	if len(all) > 1 {
		list := strings.SplitN(all[1], "建议：", 2)
		descs := strings.Split(list[0], "<*链接：")
		descs = strings.SplitN(strings.TrimSpace(descs[0]), "\n", 2)
		if len(descs) > 1 {
			desc = strings.TrimSpace(descs[1])
		}
	}
	return desc, nil
}

// 漏洞披露时间
func getCVEPublishTime(text string) (string, error) {
	publishTime := ""
	all := strings.SplitN(text, "发布日期：", 2)
	if len(all) > 1 {
		list := strings.SplitN(all[1], "更新日期：", 2)
		publishTime = list[0]
	}
	return publishTime, nil
}

// CVE编号
func getCVEId(cve string) (string, error) {
	return "", nil
}

// CWE编号 可能多个 example cve=CVE-2022-47460
func getCWEId(cve string) (string, error) {
	cweId := ""
	if cve == "" {
		return "", errors.New("empty cve")
	}
	var id string
	c := colly.NewCollector()
	c.OnHTML("td[data-testid='vuln-CWEs-link-0'] > a", func(element *colly.HTMLElement) {
		fmt.Printf("text11:%v\n", element.Text)
		id = element.Text
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve)
	err := c.Visit(url)
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("empty name")
	}

	list := strings.Split(id, "-")
	if len(list) > 1 {
		cweId = list[1]
	}
	return cweId, nil
}

// 参考URL 优先绿盟，没有再从NVD获取 可能多个
func getCVEReferURL(cve string) ([]string, error) {
	if cve == "" {
		return nil, errors.New("empty cve")
	}
	refers := make([]string, 0)
	c := colly.NewCollector()
	c.OnHTML("table[class='table table-sm table-responsive'] > tbody > tr > td > a", func(element *colly.HTMLElement) {
		fmt.Printf("text:%v\n", element.Text)
		refers = append(refers, element.Text)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	//err := c.Visit("https://avd.aliyun.com/detail?id=AVD-2022-25168")
	url := fmt.Sprintf("https://avd.aliyun.com/detail?id=%s", cve)
	err := c.Visit(url)
	if err != nil {
		return nil, err
	}

	// 阿里云引用为空，进一步从NVD获取
	if len(refers) == 0 {
		c := colly.NewCollector()
		c.OnHTML("td[data-testid='vuln-hyperlinks-link-0'] > a", func(element *colly.HTMLElement) {
			fmt.Printf("text1111:%v\n", element.Text)
			//refer = element.Text
			refers = append(refers, element.Text)
		})

		c.OnRequest(func(r *colly.Request) {
			fmt.Println("Visiting", r.URL)
		})

		//err := c.Visit("https://nvd.nist.gov/vuln/detail/CVE-2022-47460")
		url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve)
		err := c.Visit(url)
		if err != nil {
			return nil, err
		}
	}
	return refers, nil
}

// 漏洞评分
func getCVEScore(cve string) (float64, error) {
	if cve == "" {
		return 0, errors.New("empty cve")
	}
	var score string
	c := colly.NewCollector()
	c.OnHTML("span[class='severityDetail'] > a[id='Cvss3NistCalculatorAnchor']", func(element *colly.HTMLElement) {
		fmt.Printf("text11:%v\n", element.Text)
		score = element.Text
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve)
	//err := c.Visit("https://nvd.nist.gov/vuln/detail/CVE-2022-47460")
	err := c.Visit(url)
	if err != nil {
		return 0, err
	}
	if score == "" {
		return 0, errors.New("empty score")
	}

	list := strings.Split(score, " ")
	return strconv.ParseFloat(list[0], 64)
}

// CVSS
func getCVECVSS(cve string) (*vcss, error) {
	if cve == "" {
		return nil, errors.New("empty cve")
	}
	var vcssStr string
	c := colly.NewCollector()
	c.OnHTML("span[class='tooltipCvss3NistMetrics']", func(element *colly.HTMLElement) {
		fmt.Printf("text11:%v\n", element.Text)
		vcssStr = element.Text
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	url := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cve)
	//err := c.Visit("https://nvd.nist.gov/vuln/detail/CVE-2022-47460")
	err := c.Visit(url)
	if err != nil {
		return nil, err
	}
	if vcssStr == "" {
		return nil, errors.New("empty cvss")
	}

	vcss := &vcss{}
	// handle
	list := strings.Split(vcssStr, "/")
	fmt.Println(11, list)
	for i := 0; i < len(list); i++ {
		// vector
		if i == 1 {
			vcss.vector = vector(list[i])
		}
		// complexity
		if i == 2 {
			vcss.complexity = complexity(list[i])
		}
		// privilege
		if i == 3 {
			vcss.privilege = privilege(list[i])
		}
		// scope
		if i == 5 {
			vcss.scope = scope(list[i])
		}
		//// maturity
		//if i == 1 {
		//	vcss.vector = maturity(list[i])
		//}
		//// remediation
		//if i == 1 {
		//	vcss.vector = remediation(list[i])
		//}
		// confidentiality
		if i == 6 {
			vcss.confidentiality = confidentiality(list[i])
		}
		// integrity
		if i == 7 {
			vcss.integrity = integrity(list[i])
		}
		// harmness
		if i == 8 {
			vcss.harmness = harmness(list[i])
		}
		// scale
	}
	//fmt.Println(len(list))
	//fmt.Println(list)
	return vcss, nil
}

// 影响版本
func getCVEAffectedVersion(text string) (string, error) {
	version := ""
	all := strings.SplitN(text, "受影响系统：", 2)
	if len(all) > 1 {
		list := strings.SplitN(all[1], "描述：", 2)
		version = list[0]
	}
	return strings.TrimSpace(version), nil
}

// 参考建议
func getCVESuggestion(text string) (string, error) {
	suggestion := ""
	list := strings.SplitN(text, "建议：", 2)
	if len(list) > 1 {
		list = strings.SplitN(strings.TrimSpace(list[1]), "厂商补丁：", 2)
		if len(list) > 1 {
			list = strings.SplitN(strings.TrimSpace(list[1]), "----", 2)
			if len(list) > 1 {
				list = strings.SplitN(list[1], "浏览次数：", 2)
				suggestion = strings.TrimSpace(strings.ReplaceAll(list[0], "-", ""))
			}
		}
	}
	return suggestion, nil
}

// 参考URL 优先绿盟，没有再从NVD获取 可能多个
func getCVEExp(cve, suggestion string) (string, string, error) {
	if cve == "" {
		return "", "", errors.New("empty cve")
	}
	refers := make([]string, 0)

	exp := ""
	remedia := "None"

	c := colly.NewCollector()
	c.OnHTML("div[class='col-6 col-lg-3 pl-0'] > div[class='metric'] > div[class='metric-value']", func(element *colly.HTMLElement) {
		fmt.Printf("text11111:%v\n", element.Text)
		//refer = element.Text
		refers = append(refers, element.Text)
	})

	c.OnRequest(func(r *colly.Request) {
		fmt.Println("Visiting", r.URL)
	})

	//err := c.Visit("https://avd.aliyun.com/detail?id=AVD-2022-25168")
	url := fmt.Sprintf("https://avd.aliyun.com/detail?id=%s", cve)
	err := c.Visit(url)
	if err != nil {
		return "", "", err
	}

	// return 1 2
	if len(refers) == 4 {
		if strings.Contains(strings.ToUpper(refers[1]), "EXP") || strings.Contains(strings.ToUpper(refers[1]), "武器化") {
			exp = "Exp"
		} else if strings.Contains(strings.ToUpper(refers[1]), "POC") {
			exp = "Poc"
		}
	}

	//
	if strings.Contains(suggestion, "没有提供补丁") {
		remedia = "None"
	} else {
		if strings.Contains(suggestion, "补丁") || strings.Contains(suggestion, "修复了") {
			remedia = "OfficialFix"
			if strings.Contains(suggestion, "临时") {
				remedia = "TemporaryFix "
			}
		}
	}

	return exp, remedia, nil
}

type vcss struct {
	vector          string
	complexity      string
	privilege       string
	scope           string
	maturity        string
	remediation     string
	confidentiality string
	integrity       string
	harmness        string
	scale           string
}

// 攻击路径
func vector(arg string) string {
	output := ""
	switch arg {
	case "AV:N":
		output = "Network"
	case "AV:A":
		output = "Adjacent Network"
	case "AV:L":
		output = "Local"
	case "AV:P":
		output = "Physical"
	}
	return output
}

// 攻击复杂度
func complexity(arg string) string {
	output := ""
	switch arg {
	case "AC:L":
		output = "Low"
	case "AC:H":
		output = "High"
	}
	return output
}

// 权限要求
func privilege(arg string) string {
	output := ""
	switch arg {
	case "PR:N":
		output = "None"
	case "PR:L":
		output = "Low"
	case "PR:H":
		output = "High"
	}
	return output
}

// 影响范围
func scope(arg string) string {
	output := ""
	switch arg {
	case "S:U":
		output = "Unchanged"
	case "S:C":
		output = "Changed"
	}
	return output
}

// 成熟度
func maturity(arg string) string {
	output := "Poc"
	return output
}

// 补丁情况
func remediation(arg string) string {
	output := "None"
	return output
}

// 数据保密性
func confidentiality(arg string) string {
	output := ""
	switch arg {
	case "C:N":
		output = "None"
	case "C:L":
		output = "Low"
	case "C:H":
		output = "High"
	}
	return output
}

// 数据完整性
func integrity(arg string) string {
	output := ""
	switch arg {
	case "I:N":
		output = "None"
	case "I:L":
		output = "Low"
	case "I:H":
		output = "High"
	}
	return output
}

// 服务器危害
func harmness(arg string) string {
	output := ""
	switch arg {
	case "A:N":
		output = "None"
	case "A:L":
		output = "Low"
	case "A:H":
		output = "High"
	}
	return output
}

// 全网数量
func scale(arg string) string {
	return ""
}

// 评分
func getSeverity(score float64) string {
	if score >= 9.0 && score <= 10.0 {
		return "Critical"
	}

	if score >= 7.0 && score <= 8.9 {
		return "High"
	}

	if score >= 4.0 && score <= 6.9 {
		return "Medium"
	}

	if score >= 0.1 && score <= 3.9 {
		return "Low"
	}

	return "Low"
}

// 每年1000条，评分要7.0以上的
var text = `{
    'name': '%s',
    'description': '''%s''',
	'authors': ['tl'],
    'date': '%s',
    'license': 'MSF_LICENSE',
    'references': [
        {'type': 'cve', 'ref': '%s'},
        {'type': 'cwe', 'ref': '%s'},
        %s
    ],
    'type': 'remote_exploit_cmd_stager',
    'rank': 'excellent',
    'wfsdelay': 5,
    'targets': [
        {'platform': 'linux', 'arch': 'all'},
        {'platform': 'windows', 'arch': 'all'}
    ],
    'payload': {
        'command_stager_flavor': 'wget'
    },
        'options': {
        'rhosts': {'type': 'address', 'description': 'Host to target', 'required': True},
        'rport': {'type': 'port', 'description': 'Port to target', 'required': True},
		'otherdata': {'type': 'string', 'description': 'otherdata to target', 'required': True}
    },
    "finger": {
        "service": "",
        "version": "",
        "srvproto": ""
    },
    "metric": {
        "score": %.1f,
        "vector": "%s",
        "complexity": "%s",
        "privilege": "%s",
        "scope": "%s",
        "maturity": "%s",
        "remediation": "%s",
        "confidentiality": "%s",
        "integrity": "%s",
        "harmness": "%s",
        "scale": None,
    },
    "affected_version": """%s""",
    "suggestion": """%s"""
	}`
