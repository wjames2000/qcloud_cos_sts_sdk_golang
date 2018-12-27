package qcloud_cos_sts_sdk_golang

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

var (
	Conf  *Config
)

type Config struct {
	StsHost         string
	StsUrl          string
	StsScheme       string
	AllowPrefix     string
	SecretKey       string
	SecretId        string
	Resource        string
	Proxy           string
	Region          string
	Bucket          string
	AllowActions    string
	DurationSeconds int
}

func init(){
	Conf = &Config{"sts.api.qcloud.com",
		"sts.api.qcloud.com/v2/index.php",
		"https://",
		"*",
		"",
		"",
		"",
		"",
		"",
		"",
		"",
		1800,
	}
}
func encrypt(method, rurl string, keyValues map[string]string) (sign, params string) {
	params = sorted(keyValues)
	source := method + rurl + "?" + params
	mac := hmac.New(sha1.New, []byte(Conf.SecretKey))
	mac.Write([]byte(source))
	query := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return query, params
}

func sorted(keyValues map[string]string) string {
	kv := make([]string, 0)
	for k := range keyValues {
		kv = append(kv, k)
	}
	sort.Strings(kv)
	var str string = ""
	for _, v := range kv {
		if len(str) > 0 {
			str += "&" + v + "=" + keyValues[v]
		} else {
			str = v + "=" + keyValues[v]
		}
	}
	return str
}

func httpDo(requestUrl, proxies, data string) string {
	client := &http.Client{}
	if len(proxies) > 0 {
		urlproxy, _ := url.Parse(proxies)
		client.Transport = &http.Transport{
			Proxy: http.ProxyURL(urlproxy),
		}
	}
	req, err := http.NewRequest("POST", requestUrl, strings.NewReader(data))
	if err != nil {
		fmt.Println("http.Do failed,err=%s,url=%s", err, requestUrl)
		log.Fatal(err)
	}

	req.Header.Set("accept", "*/*")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("user-agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)")
	resp, err := client.Do(req)

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("http.Do failed,err=%s,url=%s", err, requestUrl)
		log.Fatal(err)
	}

	return string(body)
}
func RandInt64(min, max int64) int64 {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Int63n(max-min) + min
}

func GetCredential() string {
	splitIndex := strings.Index(Conf.Bucket, "-")
	bucketName := Conf.Bucket[:splitIndex]
	appid := Conf.Bucket[splitIndex+1:]
	policyEncode := fmt.Sprintf("{\"statement\":[{\"action\":[\"name/cos:PutObject\"],\"effect\":\"allow\",\"resource\":[\"qcs::cos:%s:uid/%s:prefix//%s/%s/%s\"]}],\"version\":\"2.0\"}", Conf.Region, appid, appid, bucketName, Conf.AllowPrefix)
	rdata := make(map[string]string)
	rdata["Region"] = Conf.Region
	rdata["SecretId"] = Conf.SecretId
	rdata["Timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	rdata["Nonce"] = fmt.Sprintf("%d", RandInt64(100000, 200000))
	rdata["Action"] = "GetFederationToken"
	rdata["name"] = bucketName
	rdata["policy"] = policyEncode

	signature, source := encrypt("POST", Conf.StsUrl, rdata)
	fmt.Println(source)
	fmt.Println(signature)
	return httpDo(Conf.StsScheme+Conf.StsUrl, Conf.Proxy, source+"&Signature="+signature)
}
