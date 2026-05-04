# routing/default.ncl — Xray-subset destination routing.
let h = import "../lib.ncl" in

{
  domainStrategy = "AsIs",
  rules = [
    { type = "field",
      ip = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
      outboundTag = "direct",
    },
    { type = "field", outboundTag = "default" },
  ],
} | h.RoutingFile
