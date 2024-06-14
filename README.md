# SimpleLeaderboard

初学 Redis 的练手小作品，支持推送带时间顺序的分数并生成最高分排行榜与累计分排行榜。~~并桥接至某 Java 期末作业当在线排行榜用~~


上传数据参考格式：
```
{
    "name": "我是例子",
    "history": [
        {
            "score": 14,
            "time": 1718213879,
            "verification": "1a9af526e18c432f0c232413ddc508fc"
        }
    ],
    "uuid": "c21498a3-2a45-4047-b4ff-2a9b345f9d6d"
}
```

特别地，对于用户的封禁直接采用 Redis 数据库中强制改名实现，名字不匹配时会触发 403 错误实现封禁效果。在实际使用时应把 `[BANNED_BY_ADMIN]` 修改成随机字符串以避免被整活哥绕过。（当然我觉得垃圾代码也没人用就是）
