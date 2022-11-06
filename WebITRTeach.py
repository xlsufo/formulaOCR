#!/usr/bin/env python 
# -*- coding:utf-8 -*-

#
# 公式识别 WebAPI 接口调用示例
# 运行前：请先填写Appid、APIKey、APISecret
# 运行方法：直接运行 main 即可 
# 结果： 控制台输出结果信息
# 
# 1.接口文档（必看）：https://www.xfyun.cn/doc/words/formula-discern/API.html
# 2.错误码链接：https://www.xfyun.cn/document/error-code （错误码code为5位数字）
#

import requests
import datetime
import hashlib
import base64
import hmac
import json
import re ### 正则表达式处理
from PIL import Image, ImageGrab
import io
import pyperclip


class get_result(object):
    def __init__(self,host):
        # 应用ID（到控制台获取）
        self.APPID = "5968bbe3"
        # 接口APISercet（到控制台公式识别服务页面获取）
        self.Secret = "2f11d22fe9cd0903da3fd2e5402f50f5"
        # 接口APIKey（到控制台公式识别服务页面获取）
        self.APIKey= "1369a1fb611e867279e851929e724c4d"
        
        
        # 以下为POST请求
        self.Host = host
        self.RequestUri = "/v2/itr"
        # 设置url
        # print(host)
        self.url="https://"+host+self.RequestUri
        self.HttpMethod = "POST"
        self.Algorithm = "hmac-sha256"
        self.HttpProto = "HTTP/1.1"

        # 设置当前时间
        curTime_utc = datetime.datetime.utcnow()
        self.Date = self.httpdate(curTime_utc)
        #设置测试图片文件
        self.img=ImageGrab.grabclipboard()  #从剪贴板获取图片
        self.BusinessArgs={
                "ent": "teach-photo-print",
                "aue": "raw",
            }

    def imgRead(self, path):
        with open(path, 'rb') as fo:
            return fo.read()

    def hashlib_256(self, res):
        m = hashlib.sha256(bytes(res.encode(encoding='utf-8'))).digest()
        result = "SHA-256=" + base64.b64encode(m).decode(encoding='utf-8')
        return result

    def httpdate(self, dt):
        """
        Return a string representation of a date according to RFC 1123
        (HTTP/1.1).

        The supplied date must be in UTC.

        """
        weekday = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][dt.weekday()]
        month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                 "Oct", "Nov", "Dec"][dt.month - 1]
        return "%s, %02d %s %04d %02d:%02d:%02d GMT" % (weekday, dt.day, month,
                                                        dt.year, dt.hour, dt.minute, dt.second)

    def generateSignature(self, digest):
        signatureStr = "host: " + self.Host + "\n"
        signatureStr += "date: " + self.Date + "\n"
        signatureStr += self.HttpMethod + " " + self.RequestUri \
                        + " " + self.HttpProto + "\n"
        signatureStr += "digest: " + digest
        signature = hmac.new(bytes(self.Secret.encode(encoding='utf-8')),
                             bytes(signatureStr.encode(encoding='utf-8')),
                             digestmod=hashlib.sha256).digest()
        result = base64.b64encode(signature)
        return result.decode(encoding='utf-8')

    def init_header(self, data):
        digest = self.hashlib_256(data)
        #print(digest)
        sign = self.generateSignature(digest)
        authHeader = 'api_key="%s", algorithm="%s", ' \
                     'headers="host date request-line digest", ' \
                     'signature="%s"' \
                     % (self.APIKey, self.Algorithm, sign)
        #print(authHeader)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Method": "POST",
            "Host": self.Host,
            "Date": self.Date,
            "Digest": digest,
            "Authorization": authHeader
        }
        return headers

    def get_body(self):
        # 创建一个字节流管道
        img_bytes = io.BytesIO()
        # 将图片数据存入字节流管道， format可以按照具体文件的格式填写
        self.img.save(img_bytes, format="JPEG")
        # 从字节流管道中获取二进制
        image_bytes = img_bytes.getvalue()
        audioData=image_bytes

        content = base64.b64encode(audioData).decode(encoding='utf-8')
        postdata = {
            "common": {"app_id": self.APPID},
            "business": self.BusinessArgs,
            "data": {
                "image": content,
            }
        }
        body = json.dumps(postdata)
        #print(body)
        return body


    def call_url(self):
        if self.APPID == '' or self.APIKey == '' or self.Secret == '':
            print('Appid 或APIKey 或APISecret 为空！请打开demo代码，填写相关信息。')
        else:
            code = 0
            body=self.get_body()
            headers=self.init_header(body)
            #print(self.url)
            response = requests.post(self.url, data=body, headers=headers,timeout=8)
            status_code = response.status_code
            #print(response.content)
            if status_code!=200:
                # 鉴权失败
                print("Http请求失败，状态码：" + str(status_code) + "，错误信息：" + response.text)
                print("请根据错误信息检查代码，接口文档：https://www.xfyun.cn/doc/words/formula-discern/API.html")
            else:
                # 鉴权成功
                respData = json.loads(response.text)
                #print(respData)

                 ### 处理 JSON 文本 ###
                 #此部分代码来源https://github.com/QingchenWait/QC-Formula.git
                formula_list = re.findall('"recog": {"content": "(.*?)", "element"', json.dumps(respData, ensure_ascii=False)) # 正则表达式匹配公式文本,生成一个列表。设置 ensure_ascii=False，可以使公式图片中的中文字符能够正常识别
                output_formula = ['']  # 初始化输出列表，长度比列表数据多 1 位
                for length in range(len(formula_list)+1):
                    output_formula.append('')

                for i in range (0,len(formula_list)):
                    origin_formula = formula_list[i] # 取出列表中每个公式
                    #print(origin_formula) # [调试] 输出原始公式字符串
                    # 对公式字符串进行修饰
                    cut_down_1 = origin_formula.replace("\\\\","\\") # 修正多余的双斜线
                    cut_down_2 = cut_down_1.replace(" ifly-latex-begin", "").replace(" ifly-latex-end", "") # 去掉 latex-begin 和 end 标识符
                    output_formula[i] = cut_down_2.replace("^ {", "^{").replace("_ {", "_{") # 去掉元素间影响观感的多余空格（不去掉也没关系）

                # 最终结果
                #print("公式",i + 1,": ",output_formula) ### [调试] 打印输出
                final_output = '\n'.join(output_formula) # 合并列表中的元素
                pyperclip.copy(final_output)
                print(final_output)

                # 以下仅用于调试
                code = str(respData["code"])
                if code!='0':
                    print("请前往https://www.xfyun.cn/document/error-code?code=" + code + "查询解决办法")

if __name__ == '__main__':
    ##示例:  host="rest-api.xfyun.cn"域名形式
    host = "rest-api.xfyun.cn"
    #初始化类
    gClass=get_result(host)
    gClass.call_url()
