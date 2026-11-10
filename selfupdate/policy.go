package selfupdate

import "errors"

// InstallEnabled remains false until the fork has a separately reviewed release
// and signing chain. Merely creating a Release must not enable binary replacement.
// This is deliberately not a runtime setting or environment-variable override.
const InstallEnabled = false

const InstallDisabledReason = "此二开版尚未建立经审核的独立发布与签名链，已禁用一键安装；请从 knowlet/artex-ymh 更新源码并重新编译，避免被上游版本覆盖"

var ErrInstallDisabled = errors.New(InstallDisabledReason)
