# WhatsApp Protocol Tree Node for Python

Pure Python serializer and deserializer for WhatsApp's WABinary / Protocol Tree Node binary protocol, with configurable token dictionaries and optional byte-exact round trips. Provides binary node read/write, JID encoding, packed strings, and zlib framing with no runtime dependencies.

WhatsApp 二进制节点的序列化与反序列化，Python 3.10+，运行时只使用标准库。字典从外部注入，协议代码不绑定某一份 token 表。

提供纯节点字节和 `flags + node` 明文封装两种入口，支持可选 zlib 压缩。Noise 握手、加密、TCP 三字节长度、消息发送和 Signal 内容解密由上层处理。

## 安装与测试

```sh
python -m pip install .
python -m pip install '.[test]'
python -m pytest
python -m pytest --cov=protocol_tree_node --cov-report=term-missing
```

开发环境可用 `python -m pip install -e '.[test]'`。构建 wheel/sdist：`python -m build`。

## read / write

```python
from protocol_tree_node import Attribute, Codec, JID, Node, TokenDictionary

# 随包快照是可选配置，不是 Codec 的隐式全局字典。
codec = Codec(TokenDictionary.bundled())

node = Node(
    "message",
    attrs=(
        Attribute("to", JID("123456789", "s.whatsapp.net")),
        Attribute("id", "ABCDEF"),
        Attribute("type", "text"),
    ),
    children=(Node("enc", attrs={"v": "2"}, data=b"\x00\xff\x80"),),
)

packet = codec.write(node)        # 00 + binary node（加密前明文）
decoded = codec.read(packet)
assert decoded == node

compressed = codec.write(node, compress=True)  # 02 + zlib(binary node)
assert codec.read(compressed) == node

raw = codec.write(node, framed=False)  # 纯 binary node，无 flags
assert codec.read(raw, framed=False) == node
```

需要将收到的节点按原编码形式逐字节写回时，两端开启 `preserve_wire`：

```python
decoded = codec.read(raw, framed=False, preserve_wire=True)
assert codec.write(decoded, framed=False, preserve_wire=True) == raw
```

它保留字典编号、字符串打包方式、长度头等编码布局，并从节点字段重新编码，不缓存或直接返回原始报文。默认模式仍使用原客户端 writer 的规范编码。修改字段后，保留模式会写出新值；新值与原布局不兼容或更换字典导致编号含义改变时抛 `ProtocolError`，可显式改用默认规范写入。

保留模式要求使用带布局的 read 返回对象。极端的非属性 JID 若在转换成文本时已丢失设备信息，会明确报错；不静默生成不同字节。

也可使用顶层 `read(data, dictionary=table)`、`write(node, dictionary=table)`。默认 `framed=True`；它指节点的明文封装，**不包含传输层长度或 AES-GCM 密文**。每次调用使用独立读写状态，同一个 Codec 可并发复用；调用期间不要替换其配置对象。

## 外部字典

```python
from protocol_tree_node import Codec, TokenDictionary

table = TokenDictionary.from_json("my-tokens.json")
codec = Codec(table)

# 或直接注入数组/配置服务返回值：
table = TokenDictionary(
    single=[None, "xmlstreamstart", "xmlstreamend", "iq", "id"],
    dictionaries=[["custom-tag", "custom-value"]],
)
codec = Codec(table)
```

JSON 结构：

```json
{
  "single": [null, "xmlstreamstart", "xmlstreamend", "iq", "id"],
  "dictionaries": [["custom-tag", "custom-value"]]
}
```

数组位置就是协议编号，不能删除中间空槽来压缩表。主表最多 236 项；扩展表最多四页，每页最多 256 项。未使用位置用 `null`；缺少页或短数组也允许。主表 0/1/2 是保留位置，不作为普通字符串发出。同词多处出现时，编码选最后一处，解码支持各处。输入数组在构造时复制，公开属性为只读 tuple。

随包表位于 `src/protocol_tree_node/data/tokens.json`，共 1260 个槽位。切换字典只需更换配置或构造另一个 Codec。

## 对象模型

- `Node(tag, attrs=(), data=None, children=None)`：tag 是非空字符串，data 为任意 `bytes`。
- `Attribute(name, value)`：值为字符串、`JID` 或 `None`。
- attrs 支持有序 Attribute 序列或有序 mapping；要保留重复属性，使用 Attribute 序列。
- data 与 children 不可同时非 None。空 `b""` 与无内容不同。
- 空 children 写出时按原 writer 行为归一为无内容；重新读取为 `children=None`。
- `STREAM_END` 对应根节点流结束：未压缩包 `00 F8 01 02`。

显式的 `JID` 避免猜测字符串是否属于某种 App 内部 JID 类型。普通字符串值保持字符串编码；原 App 的类型识别/属性名校验属于调用方适配层。

```python
from protocol_tree_node import JID

ordinary = JID("123", "s.whatsapp.net")                  # FA
device = JID("123", "lid", device=2, flags=1)           # F7
hosted = JID("123", "hosted", device=99, flags=128)     # F7
interop = JID("123", "interop", device=258, integrator=513)  # F4
group = JID("group", "interop.g.us", integrator=0)      # F4
```

`integrator` 非 None 才选择 F4，F4 的 `interop` 用户必须非空。仅有 `server="interop"` 或 `server="interop.g.us"`、未设置 integrator/device/flags 的对象仍表示普通 FA tuple；域名本身不强制某种 wire 格式。

F7 的 flags 为 0/1/128/129 时，server 分别为 `s.whatsapp.net/lid/hosted/hosted.lid`。读入时保留完整 flags；构造时若 device 非零且省略 flags，writer 按 server 推导 flags。因此对象要直接相等时应显式提供 flags；生成后再读取/写回的编码保持稳定。普通 FA 的空 user 写为 null，读取为 `None`。

字节和对象可以转换为 JSON 友好的数据：

```python
document = node.to_dict()
assert Node.from_dict(document) == node
```

`attrs` 使用 `[name, value]` 列表以保留顺序和重复项，JID 值使用 `{"jid": {...}}`，`data` 使用标准 Base64 文本或 null。JSON 只是应用层表示，不能直接当作协议字节。

## 编码与错误处理

实现列表 00/F8/F9、单/双字节字典、FC/FD/FE 字节长度、FF 数字和 FB 大写 HEX 打包、FA/F7/F4 JID，以及可选的 zlib 封装。数字表包括 `0–9`、`-`、`.`、`:`；允许打包的属性字符串在 UTF-8 长度小于 128 时尝试打包。节点 data 始终写为原始字节。

`read` 要求消耗完整输入；畸形、截断、尾随数据、未知 token/flags、分片、非法文本和超限数据抛 `ProtocolError`（ValueError 子类）。它对以下输入比 App reader 更严格：UTF-8 文本必须有效；仅允许 flags 0/2；stream end 只能是单元素根；拒绝尾随节点和 zlib 后缀。原始 data 不要求有效 UTF-8。FD 高四位、FE 最高位和奇数 packed 的末尾半字节按原 reader 规则忽略。

```python
from protocol_tree_node import Codec, Limits, ProtocolError

codec = Codec(table, limits=Limits(
    max_bytes=16 * 1024 * 1024,  # 输入、展开后的节点和输出的上限
    max_depth=128,
    max_nodes=100_000,
    max_attributes=32_767,
))
try:
    codec.read(b"\x00\xf8")
except ProtocolError as error:
    print(error)
```

max_depth 的可配置上限为 256；根节点计入深度和节点数量。zlib 解压有输出长度约束，不先无界解压再检查。

默认 `write(read(data))` 生成规范编码，非规范长度头、内容字符串 token、空子列表和字典别名可能改变字节。开启 `preserve_wire=True` 可保留节点的编码选择；`Node.to_dict()/from_dict()` 只保存节点语义，不保存这份内部布局，逐字节回写应使用原 read 返回的对象。保留模式针对节点层，不保留 zlib 实现生成的具体压缩位流；解压后节点相等和完整压缩帧相等分别验证。

## 验证

`tests/` 覆盖固定字节向量、外部字典替换、列表和长度边界、JID、Unicode/任意 bytes、压缩、截断、错误输入、资源限制、随机树、并发复用和编码布局保留。已完成 304 项测试，语句覆盖率 96.63%，其中 31 项是实际收发核验工具的合成负向与完整性检查。

样本验证工具见 `tools/`；真实原始 hook 内容应存放在本地私有目录。运行 hook 的工具单独依赖 Frida，不属于包的运行时依赖，也不通过导入包自动执行。

实际收发使用 `tools/live_hook.entry.js` 关联原生节点、加密前／解密后的明文及发送成功／接收返回。离线执行：

```sh
PYTHONPATH=src python tools/verify_live_hook.py \
  --pairs /private/path/pairs.jsonl --output /tmp/protocol-tree-node-verification.json
```

最新实际收发采集包含接收 6 条、发送 5 条，观察器错误为 0。11/11 的 Python 解析结果与原客户端对象一致，11/11 的规范写入与原客户端 writer 输出逐字节一致，11/11 开启保留模式后与原网络节点字节逐字节一致。接收样本中 4 条采用不同于原客户端 writer 的合法编码选择，这正是新增保留模式的原因。

入站规范写入的期望值来自同一个原生接收对象在内存中调用原 writer，不作为另一次网络发送。真实网络字节与该期望值独立保存。核验器要求双向调用链、原对象解析、原 writer 对照和保留模式回写全部通过。完整压缩帧是否逐字节相等单独记录。
