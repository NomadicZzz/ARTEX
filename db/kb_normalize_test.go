package db

import "testing"

func TestNormalizeProductAliases(t *testing.T) {
	cases := map[string]string{
		"Spring Cloud Gateway": "spring-cloud-gateway",
		"泛微 e-cology":          "weaver-ecology",
		"致远 OA":                "seeyon-oa",
		"Alibaba Fastjson":     "fastjson",
		"cpe:2.3:a:vmware:spring_cloud_gateway:3.1.0:*:*:*:*:*:*:*": "spring-cloud-gateway",
		"Nginx/1.18.0":  "nginx",
		"Nacos":         "nacos",
		"Apache Shiro":  "shiro",
		"帆软 FineReport": "fanruan",
	}
	for in, want := range cases {
		if got := NormalizeProduct(in); got != want {
			t.Errorf("NormalizeProduct(%q) = %q, want %q", in, got, want)
		}
	}
	if got := NormalizeProducts([]string{"Nginx", "nginx", "Spring Boot"}); len(got) != 2 {
		t.Fatalf("dedup = %v", got)
	}
}
