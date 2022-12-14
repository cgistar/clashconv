#!/usr/bin/env python
# -*- coding: utf-8 -*-

import asyncio
import base64
import collections
import logging
import os
import re
import httpx
import tempfile
import orjson as json
import uvicorn
import yaml
from fastapi import FastAPI, Query, Header, Request
from fastapi.responses import HTMLResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import List, Optional, Union
from urllib.parse import urlsplit, unquote, parse_qsl
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    pass

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
app = FastAPI()


def ordered_yaml_load(stream, Loader=yaml.SafeLoader, object_pairs_hook=collections.OrderedDict):
    class OrderedLoader(Loader):
        pass

    def _construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping)
    return yaml.load(stream, OrderedLoader)


def ordered_yaml_dump(data, stream=None, Dumper=yaml.SafeDumper, object_pairs_hook=collections.OrderedDict, **kwds):
    class OrderedDumper(Dumper):
        pass

    def _dict_representer(dumper, data):
        return dumper.represent_mapping(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, data.items())

    OrderedDumper.add_representer(object_pairs_hook, _dict_representer)
    return yaml.dump(data, stream, OrderedDumper, **kwds)


class ClashConv:
    def __init__(self, fileName=None) -> None:
        self._platform = "undefine"
        self.countrys = collections.OrderedDict()
        self.countrys["香港"] = "🇭🇰香港"
        self.countrys["台湾"] = "🇨🇳台湾"
        self.countrys["新加坡"] = "🇸🇬新加坡"
        self.countrys["日本"] = "🇯🇵日本"
        self.countrys["韩国"] = "🇰🇷韩国"
        self.countrys["印度"] = "🇮🇳印度"
        self.countrys["美国"] = "🇺🇸美国"
        self.countrys["俄罗斯"] = "🇷🇺俄罗斯"
        self.countrys["德国"] = "🇩🇪德国"
        self.countrys["澳大利亚"] = "🇦🇺澳大利亚"
        self.countrys["阿联酋"] = "🇦🇪阿联酋"
        self.countrys["波兰"] = "🇵🇱波兰"
        self.countrys["土耳其"] = "🇹🇷土耳其"
        self.countrys["加拿大"] = "🇨🇦加拿大"
        self.countrys["法国"] = "🇫🇷法国"
        self.countrys["英国"] = "🇬🇧英国"
        self.countrys["荷兰"] = "🇳🇱荷兰"
        if fileName and os.path.exists(fileName):
            f = open(fileName, "r", encoding="utf-8")
            self._stream = f.read()
            f.close()

    @property
    def platform(self):
        return self._platform

    @platform.setter
    def platform(self, platform):
        self._platform = platform

    def _yaml_load(self):
        return ordered_yaml_load(self._stream)

    def _yaml_dump(self, data):
        return ordered_yaml_dump(data, allow_unicode=True, default_flow_style=False)

    def b64decode(self, text) -> str:
        if isinstance(text, str):
            encode_bytes = text.encode()
        elif isinstance(text, bytes):
            encode_bytes = text
        add = 4 - (len(encode_bytes) % 4)
        if add:
            encode_bytes += b"=" * add
        return base64.b64decode(encode_bytes).decode("utf-8")

    def _parse_ss(self, url):
        node = dict()
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        userpass = self.b64decode(url.username).split(":")
        node["cipher"] = userpass[0]
        node["password"] = userpass[1]
        return node

    def _parse_trojan(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = "trojan"
        node["password"] = url.username
        node["udp"] = True
        if query.get("sni"):
            node["sni"] = query["sni"]
        node["skip-cert-verify"] = False
        if query.get("allowInsecure"):
            node["skip-cert-verify"] = True
        return node

    def _parse_vmess(self, url):
        node = dict()
        info = json.loads(self.b64decode(url[1]))
        node["name"] = info["ps"]
        node["server"] = info["add"]
        node["port"] = info["port"] or "443"
        node["type"] = url.scheme
        node["uuid"] = info["id"]
        node["alterId"] = info.get("aid") or "0"
        node["cipher"] = info.get("scy") or "auto"
        node["udp"] = True
        node["network"] = info["net"]
        path = info.get("path") or "/"
        if info.get("tls"):
            node["tls"] = True
        # else:
        #     node["skip-cert-verify"] = True
        if node["network"] == "ws":
            opts = dict()
            opts["path"] = path
            opts["max-early-data"] = 2048
            opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            if info.get("host"):
                if self.platform not in ("linux", "macos"):
                    opts["headers"] = {"Host": info["host"]}
            node["ws-opts"] = opts
            # node["ws-path"] = path
            # if info.get("host"):
            #     node["ws-headers"] = {"Host": info["host"]}
        if node["network"] == "h2":
            opts = dict()
            opts["path"] = path
            if info.get("host"):
                opts["host"] = list(map(str.strip, info["host"].split(",")))
            node["h2-opts"] = opts
        node["port"] = int(node["port"])
        node["alterId"] = int(node["alterId"])
        return node

    def _parse_vless(self, url):
        node = dict()
        query = dict(parse_qsl(url.query))
        path = query.get("path") or "%2F"
        path = unquote(path)
        network = query.get("type") or "http"
        # { udp: true, sni: 13-251-128-188.nhost.00cdn.com, : true }
        node["name"] = unquote(url.fragment)
        node["server"] = url.hostname
        node["port"] = url.port
        node["type"] = url.scheme
        node["uuid"] = url.username
        if query.get("sni"):
            node["servername"] = query["sni"]
        security = query.get("security")
        if security == "xtls":
            node["flow"] = query.get("flow") or "xtls-rprx-direct"
        elif security == "tls":
            node["tls"] = True
            node["udp"] = True
            node["network"] = network
            if network == "ws":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["ws-opts"] = opts
            elif network == "http":
                opts = dict()
                opts["path"] = path
                if query.get("host"):
                    opts["headers"] = {"Host": unquote(query["host"])}
                node["h2-opts"] = opts
            elif network == "grpc":
                opts = dict()
                opts["grpc-service-name"] = unquote(query["host"])
                node["grpc-opts"] = opts

        return node

    def _clash_decode(self, s):
        if not s:
            return None
        o = urlsplit(s)
        t = o.scheme
        try:
            if t == "ss":
                return self._parse_ss(o)
            elif t == "trojan" or t == "trojan-go":
                return self._parse_trojan(o)
            elif t == "vmess":
                return self._parse_vmess(o)
            elif t == "vless":
                return self._parse_vless(o)
        except Exception as e:
            logger.error(e)
        return None

    async def download_rule(self, url):
        """
        下载规则文件
        """
        cwd = tempfile.gettempdir()
        filename = os.path.basename(url)
        filepath = os.path.join(cwd, filename)
        if os.path.exists(filepath):
            return filepath
        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url)
                if response.is_success:
                    f = open(filepath, "wb")
                    f.write(response.content)
                    f.close
                    return filepath
            except Exception:
                logger.error(f"下载失败: {url}")
        return None

    def get_rule(self, groupname, files: list):
        rules = []
        ip_rules = []
        for filepath in files:
            if not os.path.exists(filepath):
                continue

            # 从下载的文件中读取配置项
            with open(filepath, "rt", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("DOMAIN") or line.startswith("SOURCE") or line.startswith("GEOIP"):
                        rules.append(f"{line.strip()},{groupname}")
                    elif line.startswith("IP-CIDR"):
                        rule = list(map(str.strip, line.split(",")))
                        if rule[-1] == "no-resolve":
                            ip_rules.append("{},{},{}".format(",".join(rule[:-1]), groupname, rule[-1]))
                        else:
                            ip_rules.append(f"{line.strip()},{groupname}")
        rules = sorted(list(set(rules)))
        if ip_rules:
            rules.extend(sorted(list(set(ip_rules))))
        return rules

    def _clash_proxies(self, nodes):
        """
        解析clash格式节点数据
        """
        proxies = []
        for node in nodes:
            proxy = self._clash_decode(node)
            if proxy:
                proxies.append(proxy)
        return proxies

    def _clash_proxy_groups(self, proxies, cfg_groups):
        """
        clash 代理组
        """
        test_params = {"url": "http://www.gstatic.com/generate_204", "interval": 300}

        groups = collections.defaultdict(list)
        nodeNames = [x["name"] for x in proxies]

        addNodes = set()
        for p in nodeNames:
            if p.find("test") >= 0 or p.find("测试") >= 0:
                addNodes.add(p)
                groups["测试线路"].append(p)
        n = set(nodeNames) - addNodes
        nodeNames = [x for x in nodeNames if x in n]

        # 收集各国专线
        pattern = re.compile(r"0\.\d+?")
        for name, flag in self.countrys.items():
            addNodes = set()
            for p in nodeNames:
                if p.find(name) >= 0:
                    addNodes.add(p)
                    if pattern.search(p):
                        groups[f"{flag}优惠"].append(p)
                    elif p.find("专线") >= 0:
                        groups[f"{flag}专线"].append(p)
                    elif p.find("倍扣") >= 0:
                        groups["多倍扣费"].append(p)
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        # 剩余解析不了的，全部归入其它
        groups["其它"] = list(nodeNames)

        allNodes = []
        autoNodes = []
        proxyGroups = []
        for item in groups.keys():
            g = {}
            if item == "倍扣":
                g = {"name": "多倍扣费", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item in ("test", "测试"):
                g = {"name": "测试线路", "type": "select", "proxies": sorted(groups[item])}
                autoNodes.append(g["name"])
            elif item == "其它":
                g = {"name": item, "type": "select", "proxies": sorted(groups[item])}
            else:
                g = {"name": item, "type": "url-test", "proxies": sorted(groups[item]), **test_params}
                autoNodes.append(item)
            if g.get("proxies"):
                allNodes.extend(g["proxies"])
                proxyGroups.append(g)

        result = []
        exclude = ("DIRECT", "REJECT")
        for group in cfg_groups:
            if not group.get("proxies") or group["name"] in exclude:
                continue
            rec = group.copy()
            if rec.get("hosts"):
                rec.pop("hosts")
            proxies = []
            for proxy in rec["proxies"]:
                if proxy == "@全部节点":
                    proxies.extend(allNodes)
                elif proxy == "@国家节点":
                    proxies.extend(autoNodes)
                else:
                    proxies.append(proxy)
            rec["proxies"] = proxies
            if rec["type"] == "url-test":
                rec.update(test_params)
            result.append(rec)
        result.extend(proxyGroups)
        return result

    def rules_local_netware(self):
        rules = "DOMAIN-SUFFIX,ip6-localhost,DIRECT DOMAIN-SUFFIX,ip6-loopback,DIRECT DOMAIN-SUFFIX,lan,DIRECT DOMAIN-SUFFIX,local,DIRECT DOMAIN-SUFFIX,localhost,DIRECT DOMAIN,instant.arubanetworks.com,DIRECT DOMAIN,setmeup.arubanetworks.com,DIRECT DOMAIN,router.asus.com,DIRECT DOMAIN-SUFFIX,hiwifi.com,DIRECT DOMAIN-SUFFIX,leike.cc,DIRECT DOMAIN-SUFFIX,miwifi.com,DIRECT DOMAIN-SUFFIX,my.router,DIRECT DOMAIN-SUFFIX,p.to,DIRECT DOMAIN-SUFFIX,peiluyou.com,DIRECT DOMAIN-SUFFIX,phicomm.me,DIRECT DOMAIN-SUFFIX,router.ctc,DIRECT DOMAIN-SUFFIX,routerlogin.com,DIRECT DOMAIN-SUFFIX,tendawifi.com,DIRECT DOMAIN-SUFFIX,zte.home,DIRECT DOMAIN-SUFFIX,tplogin.cn,DIRECT"
        return rules.split()

    def rules_suffix(self, proxyName):
        """
        后续添加的规则
        """
        return [
            "DOMAIN-KEYWORD,aria2,DIRECT",
            "DOMAIN-KEYWORD,xunlei,DIRECT",
            "DOMAIN-KEYWORD,yunpan,DIRECT",
            "DOMAIN-KEYWORD,Thunder,DIRECT",
            "DOMAIN-KEYWORD,XLLiveUD,DIRECT",
            "GEOIP,CN,DIRECT",
            f"MATCH,{proxyName}",
        ]

    async def parse_base_nodes(self, nodes):
        result = dict()
        result["mixed-port"] = 7890
        result["allow-lan"] = True
        result["bind-address"] = "*"
        result["mode"] = "rule"
        result["log-level"] = "info"
        result["external-controller"] = "127.0.0.1:9090"
        result["proxies"] = self._clash_proxies(nodes)

        # 解析配置文件
        config_path = os.path.join(os.getcwd(), "rules.yaml")
        default_proxy = ""
        cfg_groups = []
        cfg_providers = {}
        cfg_rules = [
            "IP-CIDR,198.18.0.1/16,REJECT,no-resolve",
            "GEOIP,private,DIRECT,no-resolve",
        ]
        cfg_rules.extend(self.rules_local_netware())
        if os.path.exists(config_path):
            with open(config_path, 'rt', encoding="utf-8") as f:
                cfg = yaml.load(f, Loader=yaml.FullLoader)
            if cfg.get("rule-providers"):
                for k, v in cfg["rule-providers"].items():
                    provider = v
                    provider.setdefault("interval", 3600)
                    proxy = "DIRECT"
                    if provider.get("proxy"):
                        proxy = provider.pop("proxy")
                    cfg_rules.append("RULE-SET,{},{}".format(k, proxy))
                    cfg_providers[k] = provider
            if cfg.get("proxy_groups"):
                cfg_groups = cfg["proxy_groups"]
                for x in cfg_groups:
                    if not default_proxy:
                        default_proxy = x["name"]
                    if x.get("default"):
                        default_proxy = x["name"]
                    if x.get("hosts"):
                        tasks = [self.download_rule(url) for url in x["hosts"]]
                        pages = await asyncio.gather(*tasks)
                        files = [page for page in pages if page]
                        rules = self.get_rule(x["name"], files)
                        if rules:
                            cfg_rules.extend(rules)

        result["proxy-groups"] = self._clash_proxy_groups(result["proxies"], cfg_groups)

        if cfg_providers:
            result["rule-providers"] = cfg_providers
        result["rules"] = cfg_rules
        result["rules"].extend(self.rules_suffix(default_proxy))
        return result


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request, exc):
    return HTMLResponse(str(exc.detail), status_code=exc.status_code)


@app.get("/")
def hello():
    return HTMLResponse("hello!")


@app.get("/subconv")
async def get_sub(*, url: Union[List[str], None] = Query(None), user_agent: Optional[str] = Header(None)):
    sites = []
    subConv = ClashConv()
    if user_agent:
        logger.info(f"User-Agent: {user_agent}")
        if user_agent.find("macOS") > 0 or user_agent.find("Macintosh") > 0:
            subConv.platform = "macos"
        elif user_agent.find("Linux") > 0:
            subConv.platform = "linux"
        elif user_agent == "Clash":
            subConv.platform = "linux"
    for x in url:
        async with httpx.AsyncClient() as client:
            try:
                logger.info(f"get: {x}")
                response = await client.get(x)
                if not response.is_success:
                    raise ValueError(f"获取订阅失败: {x}")
            except Exception:
                raise ValueError(f"获取订阅失败: {x}")
        s = response.content.decode()
        nodes = subConv.b64decode(s).split("\n")
        sites.extend(nodes)
    content = await subConv.parse_base_nodes(sites)
    result = yaml.safe_dump(content, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return Response(result, media_type="application/yaml")


@app.post("/subconv")
async def post_sub(request: Request):
    body = await request.body()
    subConv = ClashConv()
    nodes = subConv.b64decode(body).split("\n")
    content = await subConv.parse_base_nodes(nodes)
    result = yaml.safe_dump(content, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return Response(result, media_type="application/yaml")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
