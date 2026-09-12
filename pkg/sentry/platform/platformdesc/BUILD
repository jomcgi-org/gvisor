load("//tools:defs.bzl", "go_library", "go_test")

package(
    default_applicable_licenses = ["//:license"],
    licenses = ["notice"],
)

go_library(
    name = "platformdesc",
    srcs = [
        "platformdesc.go",
        "platformdesc_amd64.go",
    ],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/fd",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)

go_test(
    name = "platformdesc_test",
    srcs = ["platformdesc_test.go"],
    embed = [":platformdesc"],
    deps = ["@org_golang_x_sys//unix:go_default_library"],
)
