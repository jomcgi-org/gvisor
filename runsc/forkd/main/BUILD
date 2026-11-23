load("//tools:defs.bzl", "go_binary")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_binary(
    name = "forkd",
    srcs = ["main.go"],
    noasan = True,
    pure = True,
    visibility = [
        "//:sandbox",
        "//runsc/forkd:__subpackages__",
        "//test:__subpackages__",
    ],
    deps = [
        "//runsc/config",
        "//runsc/flag",
        "//runsc/forkd",
        "//runsc/specutils",
    ],
)
