package server

import (
	"path/filepath"
	"testing"

	"github.com/Autumn-27/norma/skill"
)

func TestBundledReverseEngineeringSkillsLoad(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("load bundled skills: %v", err)
	}

	want := []string{
		"reverse-engineering-router",
		"analyzing-android-malware-with-apktool",
		"analyzing-linux-elf-malware",
		"analyzing-golang-malware-with-ghidra",
		"analyzing-packed-malware-with-upx-unpacker",
		"deobfuscating-javascript-malware",
		"analyzing-uefi-bootkit-persistence",
		"analyzing-network-traffic-of-malware",
		"analyzing-malware-behavior-with-cuckoo-sandbox",
	}
	for _, name := range want {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("bundled skill %q was not loaded", name)
		}
	}
}

func TestBundledEngagementSkillsLoad(t *testing.T) {
	reg, err := skill.LoadDir(filepath.Join("..", "skills"))
	if err != nil {
		t.Fatalf("load managed skills: %v", err)
	}
	for _, name := range []string{
		"authorized-pentest-router",
		"authorized-red-team-operations",
		"conducting-internal-network-penetration-test",
		"conducting-cloud-penetration-testing",
		"conducting-mobile-app-penetration-test",
		"conducting-social-engineering-penetration-test",
	} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("managed skill %q was not loaded", name)
		}
	}
}
