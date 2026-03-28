import ServiceManagement

func installHelper() throws {
    let service = SMAppService.agent(plistName: "com.CXM87Z432P.alp.helper.plist")
    try service.register()
}

func uninstallHelper() throws {
    let service = SMAppService.agent(plistName: "com.CXM87Z432P.alp.helper.plist")
    try service.unregister()
}
