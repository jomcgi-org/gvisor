load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "forkd",
    srcs = [
        "assert.go",
        "cgroup.go",
        "child.go",
        "client.go",
        "conn.go",
        "gvisor.go",
        "net.go",
        "protocol.go",
        "runtime.go",
        "seed.go",
        "server.go",
    ],
    visibility = [
        "//:sandbox",
        "//test:__subpackages__",
    ],
    deps = [
        "//pkg/urpc",
        "//runsc/boot/sentryapi",
        "//runsc/config",
        "//runsc/container",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
        "@com_github_vishvananda_netlink//:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "forkd_test",
    size = "small",
    srcs = [
        "fake_runtime_test.go",
        "forkd_test.go",
    ],
    embed = [":forkd"],
    deps = [
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "forkd_integration_test",
    size = "large",
    srcs = ["forkd_integration_test.go"],
    data = [
        "//:release",
    ],
    tags = [
        "manual",
        "requires-kvm",
    ],
    deps = [
        ":forkd",
        "//pkg/test/testutil",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)
