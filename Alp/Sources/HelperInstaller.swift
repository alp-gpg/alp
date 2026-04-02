import ServiceManagement

func installHelper() throws {
    let service = SMAppService.agent(plistName: BuildConfig.helperPlistName)
    try service.register()
}

func uninstallHelper() throws {
    let service = SMAppService.agent(plistName: BuildConfig.helperPlistName)
    try service.unregister()
}
