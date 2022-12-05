#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import collections
import logging
import os
import re
import requests
import tempfile
import json
import yaml
from flask import Flask, request
from urllib.parse import urlsplit, unquote, parse_qsl
from werkzeug.exceptions import HTTPException

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()
app = Flask(__name__)


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


class SubConv:
    def __init__(self, fileName=None) -> None:
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
        if fileName:
            f = open(fileName, "r", encoding="utf-8")
            self._stream = f.read()
            f.close()

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
        if node["network"] == "ws":
            opts = dict()
            opts["path"] = path
            opts["max-early-data"] = 2048
            opts["early-data-header-name"] = "Sec-WebSocket-Protocol"
            if info.get("host"):
                opts["headers"] = {"Host": info["host"]}
            node["ws-opts"] = opts
            node["ws-path"] = path
            if opts.get("headers"):
                node["ws-headers"] = {"Host": info["host"]}
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

    def _sub_decode(self, s):
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

    def download_rules(self, urls: list):
        """
        下载规则文件
        """
        cwd = tempfile.gettempdir()     # os.getcwd()
        for url in urls:
            filename = os.path.basename(url)
            filepath = os.path.join(cwd, filename)
            if not os.path.exists(filepath):
                response = requests.get(url)
                if response.ok:
                    with open(filepath, "wb") as f:
                        f.write(response.content)

    def get_rule(self, groupname, urls: list):
        self.download_rules(urls)
        rules = []
        cwd = tempfile.gettempdir()     # os.getcwd()
        for url in urls:
            filename = os.path.basename(url)
            filepath = os.path.join(cwd, filename)

            # 从下载的文件中读取配置项
            with open(filepath, "rt", encoding="utf-8") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("DOMAIN") or line.startswith("SOURCE") or line.startswith("GEOIP"):
                        rules.append(f"{line.strip()},{groupname}")
                    elif line.startswith("IP-CIDR"):
                        rule = list(map(str.strip, line.split(",")))
                        if rule[-1] == "no-resolve":
                            rules.append("{},{},{}".format(",".join(rule[:-1]), groupname, rule[-1]))
                        else:
                            rules.append(f"{line.strip()},{groupname}")
        return sorted(list(set(rules)))

    def build_rule(self):
        config = [
            [
                "🛑 全球拦截",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list",
            ],
            [
                "🎯 全球直连",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/UnBan.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaMedia.list",
            ],
            [
                "🍎 苹果",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Apple.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AppleTV.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/AppleNews.list",
            ],
            ["🎥 奈飞", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list"],
            [
                "📹 YouTube",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list",
                "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list",
            ],
            ["🎮 Steam", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Steam.list"],
            ["Ⓜ️ 微软", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list"],
            ["🎶 Spotify", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Spotify.list"],
            ["🌍 Github", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Github.list"],
            ["DIRECT", "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"],
        ]
        rules = [
            "IP-CIDR,198.18.0.1/16,REJECT,no-resolve",
            "GEOIP,private,DIRECT,no-resolve",
            "RULE-SET,personal,DIRECT"
        ]
        for x in config:
            r = self.get_rule(x[0], x[1:])
            rules.extend(r)
        add_rule = [
            "RULE-SET,Custom,自定义",
            "DOMAIN-KEYWORD,aria2,🎯 全球直连",
            "DOMAIN-KEYWORD,xunlei,🎯 全球直连",
            "DOMAIN-KEYWORD,yunpan,🎯 全球直连",
            "DOMAIN-KEYWORD,Thunder,🎯 全球直连",
            "DOMAIN-KEYWORD,XLLiveUD,🎯 全球直连",
            "GEOIP,CN,🎯 全球直连",
            "MATCH,🐟 漏网之鱼",
        ]
        rules.extend(add_rule)
        return rules

    def parse_base_nodes(self, nodes):
        test_params = {"url": "http://www.gstatic.com/generate_204", "interval": 300}
        result = dict()
        result["mixed-port"] = 7890
        result["allow-lan"] = True
        result["bind-address"] = "*"
        result["mode"] = "rule"
        result["log-level"] = "info"
        result["external-controller"] = "127.0.0.1:9090"
        proxies = []
        result["proxies"] = proxies

        nodeNames = []
        for node in nodes:
            proxie = self._sub_decode(node)
            if proxie:
                proxies.append(proxie)
                nodeNames.append(proxie["name"])

        allNodes = []
        autoNodes = []
        otherNodes = []
        groups = collections.defaultdict(list)
        for item in ["倍扣", "test", "测试"]:
            addNodes = set()
            for p in nodeNames:
                if p.find(item) >= 0:
                    addNodes.add(p)
                    groups[item].append(p)
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
                    else:
                        groups[flag].append(p)
            n = set(nodeNames) - addNodes
            nodeNames = [x for x in nodeNames if x in n]

        groups["其它"] = list(nodeNames)
        result["proxy-groups"] = []

        proxyGroups = []
        for item in groups.keys():
            g = {}
            if item == "倍扣":
                g = {"name": "多倍扣费", "type": "select", "proxies": sorted(groups[item])}
                otherNodes.append(g["name"])
            elif item in ("test", "测试"):
                g = {"name": "测试线路", "type": "select", "proxies": sorted(groups[item])}
                otherNodes.append(g["name"])
            elif item == "其它":
                g = {"name": item, "type": "select", "proxies": sorted(groups[item])}
            else:
                # name = f"{item}自动"
                g = {"name": item, "type": "url-test", "proxies": sorted(groups[item]), **test_params}
                autoNodes.append(item)
            if g.get("proxies"):
                allNodes.extend(g["proxies"])
                proxyGroups.append(g)
        autoNodes.extend(otherNodes)
        result["rule-providers"] = {
            "Custom": {
                "type": "http",
                "behavior": "classical",
                "path": "./rule_provider/Custom",
                "url": "https://brinfo.cc/clash/rule_provider/Custom.yaml",
                "interval": 3600,
            },
            "personal": {
                "type": "http",
                "behavior": "classical",
                "path": "./rule_provider/personal",
                "url": "https://brinfo.cc/clash/rule_provider/personal.yaml",
                "interval": 3600,
            },
        }
        result["proxy-groups"] = [
            {"name": "🔰 节点选择1", "type": "select", "proxies": allNodes},
            {"name": "🔰 节点选择2", "type": "select", "proxies": allNodes},
            {"name": "♻️ 自动选择", "type": "url-test", "proxies": autoNodes, **test_params},
            {"name": "🎯 全球直连", "type": "select", "proxies": ["DIRECT"]},
            {"name": "🛑 全球拦截", "type": "select", "proxies": ["REJECT", "DIRECT"]},
            {"name": "Ⓜ️ 微软", "type": "select", "proxies": ["🎯 全球直连", "♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🌍 Github", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🎮 Steam", "type": "select", "proxies": ["🎯 全球直连", "♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🎶 Spotify", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🍎 苹果", "type": "select", "proxies": ["🎯 全球直连", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🎥 奈飞", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "📹 YouTube", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "自定义", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", *autoNodes]},
            {"name": "🐟 漏网之鱼", "type": "select", "proxies": ["♻️ 自动选择", "🔰 节点选择1", "🔰 节点选择2", "🎯 全球直连", *autoNodes]},
        ]
        result["proxy-groups"].extend(proxyGroups)
        result["rules"] = self.build_rule()
        return result


@app.errorhandler(Exception)
def handle_error(e):
    code = 500
    if isinstance(e, HTTPException):
        code = e.code
        logger.info(e)
    return str(e), code


@app.route("/subconv", methods=["GET"])
def get_sub():
    urls = request.args.getlist("url")
    sites = []
    subConv = SubConv()
    for url in urls:
        response = requests.get(url)
        if not response.ok:
            raise ValueError("获取订阅失败")
        s = response.content.decode()
        nodes = subConv.b64decode(s).split("\n")
        sites.extend(nodes)
    content = subConv.parse_base_nodes(sites)
    # a = self._yaml_dump(result)
    result = yaml.safe_dump(content, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return result


@app.route("/subconv", methods=["POST"])
def post_sub():
    subConv = SubConv()
    nodes = subConv.b64decode(request.data).split("\n")
    content = subConv.parse_base_nodes(nodes)
    # a = self._yaml_dump(result)
    result = yaml.safe_dump(content, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return result


if __name__ == "__main__":
    app.run("0.0.0.0", 8080)
