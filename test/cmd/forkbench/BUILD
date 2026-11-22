load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "forkbench",
    testonly = True,
    srcs = ["forkbench.go"],
    visibility = ["//visibility:public"],
    deps = [
        "//pkg/urpc",
        "//runsc/boot/sentryapi",
        "//runsc/config",
        "//runsc/container",
        "//runsc/flag",
        "//runsc/specutils",
        "@com_github_opencontainers_runtime_spec//specs-go:go_default_library",
    ],
)
