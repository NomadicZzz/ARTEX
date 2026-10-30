package db

import "testing"

func TestSplitSpecificAndBroadProducts(t *testing.T) {
	specific, broad := SplitSpecificAndBroadProducts([]string{"nginx", "java", "Fastjson", "spring-cloud-gateway", "nacos"})
	if len(specific) != 3 || specific[0] != "fastjson" || specific[1] != "spring-cloud-gateway" || specific[2] != "nacos" {
		t.Fatalf("specific = %#v", specific)
	}
	if len(broad) != 2 || broad[0] != "nginx" || broad[1] != "java" {
		t.Fatalf("broad = %#v", broad)
	}
}

func TestSplitKeepsVersionPinnedBroadTech(t *testing.T) {
	specific, broad := SplitSpecificAndBroadProducts([]string{"nginx/1.18.0", "Apache Tomcat 9.0.96", "php"})
	if len(specific) != 2 || specific[0] != "nginx" || specific[1] != "tomcat" {
		t.Fatalf("specific = %#v", specific)
	}
	if len(broad) != 1 || broad[0] != "php" {
		t.Fatalf("broad = %#v", broad)
	}
}

func TestIsBroadBaseTech(t *testing.T) {
	for _, tok := range []string{"nginx", "java", "mysql", "Spring", "IIS"} {
		if !IsBroadBaseTech(tok) {
			t.Fatalf("%s should be broad", tok)
		}
	}
	for _, tok := range []string{"fastjson", "nacos", "weaver-ecology", "shiro"} {
		if IsBroadBaseTech(tok) {
			t.Fatalf("%s should be specific", tok)
		}
	}
}
