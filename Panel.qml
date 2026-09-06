import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui

Panel {
  id: root
  moduleName: "jellespijker.fleet"
  ipcTarget: ""
  manageIpc: false

  IpcHandler {
    target: "jellespijker.fleet"
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): void { root.refresh(true) }
    function demo(): string { root.toggleDemoMode(); return root.isDemo ? "demo" : "live" }
    function mute(pkg: string): string { root.mutePackage(pkg); return "muted " + pkg }
    function unmute(pkg: string): string { root.unmutePackage(pkg); return "unmuted " + pkg }
  }

  readonly property string script: Qt.resolvedUrl("bin/fleet-monitor").toString().replace(/^file:\/\//, "")

  readonly property color foreground: bar ? bar.barForeground : Color.foreground
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color accent: Color.accent
  readonly property color dim: Color.muted ? Color.muted : Qt.darker(foreground, 1.6)
  readonly property color safeColor: {
    var c = Color.pick("green", "")
    if (c) return c
    var g = Color.shellValues["green"]
    if (g) return g
    return Color.accent
  }
  readonly property color cardBg: Util.alpha(foreground, 0.05)
  readonly property color cardBorder: Util.alpha(foreground, 0.12)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  readonly property int barContentWidth: Style.bar.iconFont + Style.space(4)
  readonly property int barSlot: barContentWidth + Style.space(10)
  implicitWidth: bar && bar.vertical ? (bar ? bar.barSize : Style.bar.sizeHorizontal) : barSlot
  implicitHeight: bar && bar.vertical ? barSlot : (bar ? bar.barSize : Style.bar.sizeHorizontal)

  // Status & Telemetry
  property string statusState: "ok" // "ok" | "error" | "unconfigured" | "unauthenticated" | "missing_cli" | "unreachable"
  readonly property bool isSetupNeeded: root.statusState === "unconfigured" || root.statusState === "unauthenticated" || root.statusState === "missing_cli"
  readonly property bool isErrorState: root.statusState === "error" || root.statusState === "unreachable"
  property string errorMessage: ""
  property int hostsTotal: 0
  property int hostsOnline: 0
  property int hostsOffline: 0
  property int vulnerableSoftwareCount: 0
  property int totalCves: 0
  property int cisaKevActive: 0
  property int tier1Count: 0
  property int tier2Count: 0
  property int tier3Count: 0
  property int tier4Count: 0
  property int actionableCount: 0
  property int mutedCount: 0
  property var mutedItems: []
  property bool showMuted: false
  property bool isDemo: false
  property bool _initialScanDone: false
  property string lastScanTime: ""
  property string fleetUrl: ""
  property var tier1Packages: []
  property var tier2Packages: []
  property var actionablePackages: []
  property bool busy: false

  // Selected index for keyboard traversal
  property int selectedIndex: 0

  // ID of the target currently displaying \"Copied!\" feedback
  property string copiedTarget: ""

  // Icons
  readonly property string iconShieldCheck: "󰓠"
  readonly property string iconShieldAlert: "󰓟"
  readonly property string iconShieldWarning: "󰓜"
  readonly property string iconServer: "󰈗"
  readonly property string iconAlert: "󰀨"
  readonly property string iconCheck: "󰄬"
  readonly property string iconRefresh: "󰑐"
  readonly property string iconExternal: "󰌹"
  readonly property string iconCopy: "󰆏"
  readonly property string iconTerminal: "󰓰"
  readonly property string iconMute: "󰂛"
  readonly property string iconUnmute: "󰂚"
  readonly property string iconDemo: "󰈈"
  readonly property string iconRun: "󰐊"

  function applyStatus(raw) {
    busy = false
    refreshWatchdog.stop()
    if (!raw || raw.trim() === "") return
    try {
      var data = JSON.parse(raw)
      root.statusState = data.status || "ok"
      root.errorMessage = data.error_message || ""
      root.isDemo = !!data.is_demo
      root._initialScanDone = true
      root.hostsTotal = data.hosts_total !== undefined ? data.hosts_total : root.hostsTotal
      root.hostsOnline = data.hosts_online !== undefined ? data.hosts_online : root.hostsOnline
      root.hostsOffline = data.hosts_offline !== undefined ? data.hosts_offline : 0
      root.vulnerableSoftwareCount = data.vulnerable_software_count || 0
      root.totalCves = data.total_cves || 0
      root.cisaKevActive = data.cisa_kev_active || 0
      root.tier1Count = data.tier1_count || 0
      root.tier2Count = data.tier2_count || 0
      root.tier3Count = data.tier3_count || 0
      root.tier4Count = data.tier4_count || 0
      root.actionableCount = data.actionable_count || 0
      root.mutedCount = data.muted_count || 0
      root.mutedItems = data.muted_items || []
      root.lastScanTime = data.last_scan_time || ""
      root.fleetUrl = data.fleet_url || root.fleetUrl
      root.tier1Packages = data.tier1_packages || []
      root.tier2Packages = data.tier2_packages || []
      var pkgs = data.actionable_packages || []
      root.actionablePackages = []
      root.actionablePackages = pkgs
    } catch (e) {
      console.warn("Failed to parse Fleet status JSON:", e, raw)
      root.statusState = "error"
      root.errorMessage = "JSON parse error from fleet-monitor"
    }
  }

  onOpenedChanged: {
    if (root.opened) {
      root.refresh(false)
    }
  }

  function refresh(force) {
    if (statusProc.running) {
      if (force) {
        statusProc.running = false
      } else {
        return
      }
    }
    busy = true
    refreshWatchdog.restart()
    var args = [root.script, "status"]
    if (force) args.push("--force")
    root._statusOutput = ""
    root._statusError = ""
    statusProc.command = args
    statusProc.running = true
  }

  function setDemoMode(enabled) {
    if (statusProc.running) {
      statusProc.running = false
    }
    root.isDemo = enabled
    root._initialScanDone = true
    busy = true
    refreshWatchdog.restart()
    root._statusOutput = ""
    root._statusError = ""
    statusProc.command = [root.script, "demo", enabled ? "on" : "off"]
    statusProc.running = true
  }

  function toggleDemoMode() {
    root.setDemoMode(!root.isDemo)
  }

  function mutePackage(name) {
    if (!name) return
    muteProc.command = [root.script, "mute", name]
    muteProc.running = true
  }

  function unmutePackage(name) {
    if (!name) return
    unmuteProc.command = [root.script, "unmute", name]
    unmuteProc.running = true
  }

  function openFleetWeb() {
    openUiProc.command = [root.script, "open-ui"]
    openUiProc.running = true
  }

  function launchTriageTerminal() {
    var args = [root.script, "open-triage"]
    if (root.isDemo) args.push("--demo")
    else args.push("--live")
    triageProc.command = args
    triageProc.running = true
  }

  function launchSetupTerminal() {
    setupProc.command = [root.script, "open-setup"]
    setupProc.running = true
  }

  function copyAction(cmdText, targetId) {
    if (!cmdText) return
    copyProc.command = [root.script, "copy", cmdText]
    copyProc.running = true
    root.copiedTarget = targetId
    clearCopyTimer.restart()
  }

  function runFixAction(cmdText) {
    if (!cmdText) return
    runFixProc.command = [root.script, "run-fix", cmdText]
    runFixProc.running = true
  }

  Timer {
    id: clearCopyTimer
    interval: 1500
    onTriggered: root.copiedTarget = ""
  }

  Timer {
    id: refreshWatchdog
    interval: 12000
    repeat: false
    onTriggered: {
      if (root.busy) {
        root.busy = false
        if (statusProc.running) statusProc.running = false
      }
    }
  }

  property string _statusOutput: ""
  property string _statusError: ""

  // Background processes
  Process {
    id: statusProc
    stdout: StdioCollector {
      id: statusStdout
      waitForEnd: true
      onStreamFinished: root._statusOutput = text
    }
    stderr: StdioCollector {
      id: statusStderr
      waitForEnd: true
      onStreamFinished: root._statusError = text
    }
    onExited: function(exitCode) {
      refreshWatchdog.stop()
      root.busy = false
      var out = String(statusStdout.text || root._statusOutput || "")
      var err = String(statusStderr.text || root._statusError || "")
      if (exitCode === 0) {
        root.applyStatus(out)
      } else {
        console.warn("fleet-monitor process exited with code", exitCode, err)
        root.statusState = "error"
        root.errorMessage = err || ("Process exited with code " + exitCode)
      }
    }
  }

  Process {
    id: muteProc
    onExited: function() { root.refresh(true) }
  }

  Process {
    id: unmuteProc
    onExited: function() { root.refresh(true) }
  }

  Process { id: openUiProc }
  Process { id: triageProc }
  Process { id: copyProc }
  Process { id: runFixProc }
  Process {
    id: setupProc
    onExited: function() { root.refresh(true) }
  }

  // Polling: every 60s when closed, every 15s when opened
  Timer {
    interval: root.opened ? 15000 : 60000
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh(false)
  }

  Component.onCompleted: root.refresh(false)

  // Status Bar Button
  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.isSetupNeeded
      ? root.iconExternal
      : (root.isErrorState
         ? root.iconAlert
         : (root.tier1Count > 0 ? root.iconShieldAlert : (root.tier2Count > 0 ? root.iconShieldWarning : root.iconShieldCheck)))
    slotSize: root.barSlot
    opticalSize: root.barContentWidth
    active: root.isSetupNeeded || root.isErrorState || root.tier1Count > 0 || root.tier2Count > 0
    activeColor: (root.isErrorState || root.tier1Count > 0)
      ? root.urgent
      : (root.isSetupNeeded ? root.accent : (root.tier2Count > 0 ? root.accent : root.safeColor))
    useActiveColor: true
    tooltipText: root.isSetupNeeded
      ? ("Fleet Security: Setup Required (" + (root.errorMessage || "Connect to Fleet") + ")")
      : (root.isDemo
         ? ("Fleet Security [DEMO]: " + root.tier1Count + " CISA KEV Exploits (" + root.hostsTotal + " Hosts)")
         : (root.isErrorState
            ? ("Fleet Security Error: " + (root.errorMessage || "Daemon unreachable"))
            : (root.tier1Count > 0
               ? ("Fleet Security: " + root.tier1Count + " CRITICAL CISA KEV Exploits!")
               : (root.tier2Count > 0
                  ? ("Fleet Security: " + root.tier2Count + " Actionable CVE Packages (" + root.hostsTotal + " Hosts)")
                  : ("Fleet Security: All Clear (" + root.hostsTotal + " Hosts Monitored)")))))

    onPressed: function(b) {
      if (b === Qt.RightButton || b === Qt.MiddleButton) {
        root.refresh(true)
      } else {
        root.toggle()
      }
    }
  }

  // Popout Panel
  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(480))
    contentHeight: panel.fittedContentHeight(panelLayout.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onMoveRequested: function(dx, dy) {
        if (dy !== 0 && root.actionablePackages.length > 0) {
          var nextIdx = root.selectedIndex + dy
          if (nextIdx < 0) nextIdx = 0
          if (nextIdx >= root.actionablePackages.length) nextIdx = root.actionablePackages.length - 1
          root.selectedIndex = nextIdx
          if (pkgList.count > 0) {
            pkgList.positionViewAtIndex(nextIdx, ListView.Contain)
          }
        }
      }
      onActivateRequested: {
        if (root.actionablePackages.length > root.selectedIndex) {
          var item = root.actionablePackages[root.selectedIndex]
          if (item && item.action) {
            root.copyAction(item.action, "pkg:" + item.name)
          }
        }
      }
      onTextKey: function(t) {
        if (t === "r" || t === "R") root.refresh(true)
        if (t === "d" || t === "D") root.toggleDemoMode()
        if (t === "s" || t === "S") root.launchSetupTerminal()
        if (t === "x" || t === "X") {
          if (root.actionablePackages.length > root.selectedIndex) {
            var item = root.actionablePackages[root.selectedIndex]
            if (item && item.action) {
              root.runFixAction(item.action)
            }
          }
        }
      }

      ColumnLayout {
        id: panelLayout
        anchors.fill: parent
        spacing: Style.space(8)

        // 1. Header Hero
        PanelHero {
          Layout.fillWidth: true
          title: root.isDemo
            ? "Fleet Security (Demo Mode)"
            : (root.isSetupNeeded
               ? "FleetDM Setup Required"
               : (root.isErrorState ? "Fleet Telemetry Error" : "Fleet Security"))
          meta: root.isDemo
            ? "Simulated Multi-Host Telemetry"
            : (root.isSetupNeeded
               ? (root.statusState === "unauthenticated" ? "Session Expired / Auth Required" : "Connect Your Fleet Instance")
               : (root.isErrorState
                  ? "Communication Failure"
                  : (root.tier1Count > 0
                     ? (root.tier1Count + " Critical CISA KEV Exploits")
                     : (root.tier2Count > 0 ? (root.tier2Count + " Actionable Packages") : "All Systems Secure"))))
          detail: root.isDemo
            ? (root.hostsOnline + "/" + root.hostsTotal + " Hosts")
            : (root.isSetupNeeded
               ? "Not Connected"
               : (root.isErrorState
                  ? "Offline"
                  : (root.hostsOnline + "/" + root.hostsTotal + " Online" + (root.hostsOffline > 0 ? (" (" + root.hostsOffline + " off)") : ""))))
          foreground: root.foreground
          fontFamily: root.fontFamily
          iconOpacity: 1.0
          iconComponent: Component {
            Text {
              text: root.isSetupNeeded
                ? root.iconExternal
                : (root.isErrorState
                   ? root.iconAlert
                   : (root.tier1Count > 0 ? root.iconShieldAlert : (root.tier2Count > 0 ? root.iconShieldWarning : root.iconShieldCheck)))
              font.family: root.fontFamily
              font.pixelSize: Style.space(24)
              color: (root.isErrorState || root.tier1Count > 0)
                ? root.urgent
                : (root.isSetupNeeded ? root.accent : (root.tier2Count > 0 ? root.accent : root.safeColor))
            }
          }
          trailingControl: Component {
            RowLayout {
              spacing: Style.space(4)
              Button {
                text: root.isDemo ? "Demo" : "Live"
                iconText: root.isDemo ? root.iconDemo : root.iconServer
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                horizontalPadding: Style.space(6)
                verticalPadding: Style.space(2)
                selected: root.isDemo
                foreground: root.isDemo ? root.accent : root.dim
                accent: root.accent
                bordered: true
                tooltipText: root.isDemo ? "Demo active. Click to switch to live fleet telemetry (D)" : "Live active. Click to test demo fleet mode (D)"
                onClicked: root.toggleDemoMode()
              }
              Button {
                text: ""
                iconText: root.iconRefresh
                iconSpinning: root.busy
                fontFamily: root.fontFamily
                foreground: root.busy ? root.accent : root.foreground
                accent: root.accent
                bordered: false
                tooltipText: "Force vulnerability refresh (R)"
                onClicked: root.refresh(true)
              }
            }
          }
        }

        // 2. Error Recovery State Card (Shown only on connection error or unreachable)
        Rectangle {
          visible: root.isErrorState
          Layout.fillWidth: true
          implicitHeight: errCol.implicitHeight + Style.space(16)
          radius: Style.space(6)
          color: Util.alpha(root.urgent, 0.12)
          border.color: root.urgent
          border.width: 1

          ColumnLayout {
            id: errCol
            anchors.fill: parent
            anchors.margins: Style.space(10)
            spacing: Style.space(8)

            RowLayout {
              spacing: Style.space(8)
              Text {
                text: root.iconAlert
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.heading : 16
                color: root.urgent
              }
              Text {
                Layout.fillWidth: true
                text: "Fleet Daemon or Server Unreachable"
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.bodySmall : 11
                font.bold: true
                color: root.urgent
              }
            }

            Text {
              Layout.fillWidth: true
              text: root.errorMessage || "Check your network connection to the Fleet server or ensure orbit/fleetd is running."
              font.family: root.fontFamily
              font.pixelSize: Style.font ? Style.font.caption : 10
              color: root.foreground
              wrapMode: Text.Wrap
            }

            RowLayout {
              spacing: Style.space(8)
              Button {
                text: "Retry Scan"
                iconText: root.iconRefresh
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                foreground: root.foreground
                accent: root.accent
                bordered: true
                onClicked: root.refresh(true)
              }
              Button {
                text: "Explore Demo Mode"
                iconText: root.iconDemo
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                foreground: root.accent
                accent: root.accent
                bordered: true
                tooltipText: "Explore plugin features using synthetic telemetry"
                onClicked: root.setDemoMode(true)
              }
              Button {
                text: "Open Fleet UI"
                iconText: root.iconExternal
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                foreground: root.accent
                accent: root.accent
                bordered: true
                onClicked: root.openFleetWeb()
              }
            }
          }
        }

        // 2b. Bootstrap & Authentication Required Card
        Rectangle {
          visible: root.isSetupNeeded
          Layout.fillWidth: true
          implicitHeight: setupCol.implicitHeight + Style.space(24)
          radius: Style.space(8)
          color: Util.alpha(root.accent, 0.08)
          border.color: Util.alpha(root.accent, 0.35)
          border.width: 1

          ColumnLayout {
            id: setupCol
            anchors.fill: parent
            anchors.margins: Style.space(16)
            spacing: Style.space(10)

            RowLayout {
              spacing: Style.space(10)
              Text {
                text: root.statusState === "unauthenticated" ? "󰀪" : (root.statusState === "missing_cli" ? "󰅚" : "󰌹")
                font.family: root.fontFamily
                font.pixelSize: Style.space(22)
                color: root.accent
              }
              ColumnLayout {
                Layout.fillWidth: true
                spacing: Style.space(2)
                Text {
                  Layout.fillWidth: true
                  text: root.statusState === "unauthenticated"
                    ? "Fleet Session Expired"
                    : (root.statusState === "missing_cli" ? "fleetctl CLI Missing" : "Connect to FleetDM")
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.heading : 14
                  font.bold: true
                  color: root.foreground
                }
                Text {
                  Layout.fillWidth: true
                  text: root.errorMessage || "Connect your FleetDM instance to monitor CVEs and CISA KEV across your machines."
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.bodySmall : 11
                  color: root.dim
                  wrapMode: Text.Wrap
                }
              }
            }

            Rectangle {
              Layout.fillWidth: true
              height: 1
              color: root.cardBorder
            }

            // Primary Setup Wizard Button
            Button {
              Layout.fillWidth: true
              text: root.statusState === "unauthenticated" ? "Re-authenticate in Terminal (S)" : "Run Setup Wizard in Terminal (S)"
              iconText: root.iconRun
              fontFamily: root.fontFamily
              fontSize: Style.font ? Style.font.bodySmall : 11
              foreground: root.accent
              accent: root.accent
              bordered: true
              tooltipText: "Launch interactive terminal setup wizard (fleet-setup)"
              onClicked: root.launchSetupTerminal()
            }

            // Secondary: Try Demo Mode or Open Docs
            RowLayout {
              Layout.fillWidth: true
              spacing: Style.space(8)

              Button {
                Layout.fillWidth: true
                text: "Explore Demo Fleet"
                iconText: root.iconDemo
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                foreground: root.foreground
                accent: root.accent
                bordered: true
                tooltipText: "Explore plugin UI and features with realistic simulated telemetry"
                onClicked: root.setDemoMode(true)
              }

              Button {
                text: "Fleet Docs ↗"
                iconText: root.iconExternal
                fontFamily: root.fontFamily
                fontSize: Style.font ? Style.font.caption : 10
                foreground: root.dim
                accent: root.accent
                bordered: false
                tooltipText: "Open FleetDM setup documentation in browser"
                onClicked: Qt.openUrlExternally("https://fleetdm.com/docs/using-fleet/fleetctl-cli")
              }
            }
          }
        }

        // 3. Compact Stat Strip
        RowLayout {
          visible: !root.isSetupNeeded && !root.isErrorState
          Layout.fillWidth: true
          spacing: Style.space(6)

          // Pill 1: CISA KEV Exploits
          Rectangle {
            Layout.fillWidth: true
            height: Style.space(34)
            radius: Style.space(6)
            color: root.cisaKevActive > 0 ? Util.alpha(root.urgent, 0.15) : root.cardBg
            border.color: root.cisaKevActive > 0 ? root.urgent : root.cardBorder
            border.width: 1

            Row {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: root.cisaKevActive > 0 ? root.iconAlert : root.iconShieldCheck
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.bodySmall : 11
                color: root.cisaKevActive > 0 ? root.urgent : root.safeColor
              }
              Text {
                text: root.cisaKevActive + " CISA KEV"
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.caption : 10
                font.bold: true
                color: root.cisaKevActive > 0 ? root.urgent : root.foreground
              }
            }
          }

          // Pill 2: Actionable To Patch
          Rectangle {
            Layout.fillWidth: true
            height: Style.space(34)
            radius: Style.space(6)
            color: root.actionableCount > 0 ? Util.alpha(root.accent, 0.15) : root.cardBg
            border.color: root.actionableCount > 0 ? root.accent : root.cardBorder
            border.width: 1

            Row {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: root.actionableCount > 0 ? root.iconShieldWarning : root.iconCheck
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.bodySmall : 11
                color: root.actionableCount > 0 ? root.accent : root.safeColor
              }
              Text {
                text: root.actionableCount + " To Patch"
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.caption : 10
                font.bold: true
                color: root.actionableCount > 0 ? root.accent : root.foreground
              }
            }
          }

          // Pill 3: Total CVEs
          Rectangle {
            Layout.fillWidth: true
            height: Style.space(34)
            radius: Style.space(6)
            color: root.cardBg
            border.color: root.cardBorder
            border.width: 1

            Row {
              anchors.centerIn: parent
              spacing: Style.space(6)
              Text {
                text: root.iconServer
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.bodySmall : 11
                color: root.dim
              }
              Text {
                text: root.totalCves + " CVEs"
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.caption : 10
                font.bold: true
                color: root.foreground
              }
            }
          }

          // Pill 4: Muted Packages (Shown when mutedCount > 0)
          Rectangle {
            visible: root.mutedCount > 0
            Layout.fillWidth: true
            height: Style.space(34)
            radius: Style.space(6)
            color: root.showMuted ? Util.alpha(root.accent, 0.15) : root.cardBg
            border.color: root.showMuted ? root.accent : root.cardBorder
            border.width: 1

            MouseArea {
              anchors.fill: parent
              cursorShape: Qt.PointingHandCursor
              onClicked: root.showMuted = !root.showMuted
            }

            Row {
              anchors.centerIn: parent
              spacing: Style.space(4)
              Text {
                text: root.iconMute
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.bodySmall : 11
                color: root.dim
              }
              Text {
                text: root.mutedCount + " Muted"
                font.family: root.fontFamily
                font.pixelSize: Style.font ? Style.font.caption : 10
                font.bold: true
                color: root.dim
              }
            }
          }
        }

        // 4. Section Label
        RowLayout {
          visible: root.actionablePackages.length > 0 && root.statusState !== "error"
          Layout.fillWidth: true

          Text {
            text: "ACTIONABLE PACKAGES (" + root.actionablePackages.length + ")"
            font.family: root.fontFamily
            font.pixelSize: Style.font ? Style.font.caption : 10
            font.bold: true
            color: root.dim
          }

          Item { Layout.fillWidth: true }

          Text {
            text: root.lastScanTime ? ("Scanned " + root.lastScanTime) : ""
            font.family: root.fontFamily
            font.pixelSize: Style.font ? Style.font.caption : 10
            color: root.dim
          }
        }

        // Empty state: Confident, verified posture card
        Rectangle {
          visible: root.actionablePackages.length === 0 && !root.isSetupNeeded && !root.isErrorState
          Layout.fillWidth: true
          implicitHeight: emptyCol.implicitHeight + Style.space(28)
          radius: Style.space(8)
          color: Util.alpha(root.safeColor, 0.08)
          border.color: Util.alpha(root.safeColor, 0.28)
          border.width: 1

          ColumnLayout {
            id: emptyCol
            anchors.fill: parent
            anchors.margins: Style.space(16)
            spacing: Style.space(6)

            Text {
              Layout.alignment: Qt.AlignHCenter
              text: root.iconShieldCheck
              font.family: root.fontFamily
              font.pixelSize: Style.space(36)
              color: root.safeColor
            }

            Text {
              Layout.alignment: Qt.AlignHCenter
              text: "All Fleet Systems Compliant"
              font.family: root.fontFamily
              font.pixelSize: Style.font ? Style.font.heading : 14
              font.bold: true
              color: root.foreground
            }

            Text {
              Layout.alignment: Qt.AlignHCenter
              Layout.fillWidth: true
              horizontalAlignment: Text.AlignHCenter
              text: "No active CISA KEV exploits or actionable vulnerabilities found across " + root.hostsTotal + " monitored host" + (root.hostsTotal === 1 ? "" : "s") + "."
              font.family: root.fontFamily
              font.pixelSize: Style.font ? Style.font.bodySmall : 11
              color: root.dim
              wrapMode: Text.Wrap
            }

            Text {
              Layout.alignment: Qt.AlignHCenter
              visible: !!root.lastScanTime
              text: "Last audit: " + root.lastScanTime
              font.family: root.fontFamily
              font.pixelSize: Style.font ? Style.font.caption : 10
              color: Util.alpha(root.foreground, 0.4)
            }
          }
        }

        // 5. Scrollable Priority Package ListView
        ListView {
          id: pkgList
          visible: root.actionablePackages.length > 0 && !root.isSetupNeeded && !root.isErrorState
          Layout.fillWidth: true
          Layout.fillHeight: true
          Layout.preferredHeight: Math.min(contentHeight, Style.space(420))
          clip: true
          boundsBehavior: Flickable.StopAtBounds
          spacing: Style.space(8)
          ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

          model: root.actionablePackages

          delegate: Rectangle {
            id: itemRow
            required property var modelData
            required property int index

            readonly property bool isTier1: itemRow.modelData && itemRow.modelData.tier === 1
            readonly property bool isSelected: index === root.selectedIndex
            readonly property string pkgTargetId: "pkg:" + (itemRow.modelData ? itemRow.modelData.name : "")
            readonly property bool isPkgCopied: root.copiedTarget === pkgTargetId

            width: pkgList.width - (pkgList.contentHeight > pkgList.height ? Style.space(8) : 0)
            implicitHeight: itemCol.implicitHeight + Style.space(16)
            radius: Style.space(6)

            color: itemRow.isSelected
              ? Util.alpha(root.accent, 0.12)
              : (rowMouse.containsMouse
                 ? Util.alpha(root.foreground, 0.08)
                 : (itemRow.isTier1 ? Util.alpha(root.urgent, 0.05) : root.cardBg))

            border.color: itemRow.isSelected
              ? root.accent
              : (itemRow.isTier1 ? Util.alpha(root.urgent, 0.45) : root.cardBorder)
            border.width: itemRow.isSelected ? 2 : 1

            // Refined left accent rail for high-severity alerts
            Rectangle {
              id: accentRail
              width: Style.space(3)
              anchors.left: parent.left
              anchors.leftMargin: Style.space(3)
              anchors.top: parent.top
              anchors.bottom: parent.bottom
              anchors.topMargin: Style.space(6)
              anchors.bottomMargin: Style.space(6)
              radius: Style.space(2)
              color: itemRow.isTier1 ? root.urgent : (itemRow.isSelected ? root.accent : "transparent")
              visible: itemRow.isTier1 || itemRow.isSelected
            }

            MouseArea {
              id: rowMouse
              anchors.fill: parent
              hoverEnabled: true
              acceptedButtons: Qt.LeftButton
              onClicked: {
                root.selectedIndex = index
              }
            }

            ColumnLayout {
              id: itemCol
              anchors.fill: parent
              anchors.leftMargin: Style.space(12)
              anchors.rightMargin: Style.space(8)
              anchors.topMargin: Style.space(8)
              anchors.bottomMargin: Style.space(8)
              spacing: Style.space(6)

              // 1. Top row: CISA KEV Badge, Package Name, Version, Host Count, Mute Button
              RowLayout {
                Layout.fillWidth: true
                spacing: Style.space(6)

                // Tier 1 Warning Badge (if CISA KEV)
                Rectangle {
                  visible: itemRow.isTier1
                  height: Style.space(18)
                  width: t1BadgeRow.implicitWidth + Style.space(8)
                  radius: Style.space(3)
                  color: Util.alpha(root.urgent, 0.22)
                  border.color: Util.alpha(root.urgent, 0.5)
                  border.width: 1

                  Row {
                    id: t1BadgeRow
                    anchors.centerIn: parent
                    spacing: Style.space(3)
                    Text {
                      text: root.iconAlert
                      font.family: root.fontFamily
                      font.pixelSize: Style.font ? Style.font.caption : 10
                      color: root.urgent
                    }
                    Text {
                      text: "CISA KEV"
                      font.family: root.fontFamily
                      font.pixelSize: Style.font ? Style.font.caption : 10
                      font.bold: true
                      color: root.urgent
                    }
                  }
                }

                // Package Name & Version (Spacious, bold, un-crammed)
                RowLayout {
                  Layout.fillWidth: true
                  spacing: Style.space(5)

                  Text {
                    text: itemRow.modelData ? itemRow.modelData.name : ""
                    font.family: root.fontFamily
                    font.pixelSize: Style.font ? Style.font.bodySmall : 11
                    font.bold: true
                    color: root.foreground
                  }

                  Text {
                    Layout.fillWidth: true
                    text: itemRow.modelData && itemRow.modelData.version ? itemRow.modelData.version : ""
                    font.family: root.fontFamily
                    font.pixelSize: Style.font ? Style.font.caption : 10
                    color: root.dim
                    elide: Text.ElideRight
                  }
                }

                // Host count badge
                Rectangle {
                  height: Style.space(16)
                  width: hostCountText.implicitWidth + Style.space(8)
                  radius: Style.space(3)
                  color: Util.alpha(root.accent, 0.18)
                  Text {
                    id: hostCountText
                    anchors.centerIn: parent
                    text: {
                      var h = itemRow.modelData ? itemRow.modelData.hosts : 1
                      return h + (h === 1 ? " host" : " hosts")
                    }
                    font.family: root.fontFamily
                    font.pixelSize: Style.font ? Style.font.caption : 10
                    font.bold: true
                    color: root.accent
                  }
                }

                // Subtle Mute Action on Top-Right
                Button {
                  text: ""
                  iconText: root.iconMute
                  fontFamily: root.fontFamily
                  fontSize: Style.font ? Style.font.caption : 10
                  iconSize: Style.font ? Style.font.caption : 10
                  horizontalPadding: Style.space(5)
                  verticalPadding: Style.space(2)
                  foreground: root.dim
                  accent: root.urgent
                  bordered: false
                  tooltipText: "Mute alerts for " + (itemRow.modelData ? itemRow.modelData.name : "package")
                  onClicked: {
                    if (itemRow.modelData && itemRow.modelData.name) {
                      root.mutePackage(itemRow.modelData.name)
                    }
                  }
                }
              }

              // 2. Middle row: Clickable Host Chips with target-specific commands
              Flow {
                Layout.fillWidth: true
                spacing: Style.space(4)
                visible: itemRow.modelData && itemRow.modelData.host_chips && itemRow.modelData.host_chips.length > 0

                Repeater {
                  model: itemRow.modelData ? itemRow.modelData.host_chips : []
                  delegate: Rectangle {
                    id: chip
                    required property var modelData
                    readonly property string chipTargetId: "chip:" + itemRow.modelData.name + ":" + chip.modelData.name
                    readonly property bool isChipCopied: root.copiedTarget === chipTargetId

                    height: Style.space(20)
                    width: chipContentRow.implicitWidth + Style.space(6)
                    radius: Style.space(3)

                    color: chip.isChipCopied
                      ? Util.alpha(root.safeColor, 0.25)
                      : (chipMouse.containsMouse ? Util.alpha(root.foreground, 0.14) : Util.alpha(root.foreground, 0.08))

                    border.color: chip.isChipCopied
                      ? root.safeColor
                      : (chipMouse.containsMouse ? root.accent : Util.alpha(root.foreground, 0.12))
                    border.width: 1

                    Row {
                      id: chipContentRow
                      anchors.centerIn: parent
                      spacing: Style.space(4)

                      // Left target: Click to copy command
                      MouseArea {
                        id: chipMouse
                        width: chipLeftRow.implicitWidth + Style.space(4)
                        height: chip.height
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                          if (chip.modelData && chip.modelData.action) {
                            root.copyAction(chip.modelData.action, chip.chipTargetId)
                          }
                        }

                        Row {
                          id: chipLeftRow
                          anchors.centerIn: parent
                          spacing: Style.space(3)
                          Text {
                            text: chip.isChipCopied ? root.iconCheck : (chip.modelData.online ? "󰒋" : "󰒌")
                            font.family: root.fontFamily
                            font.pixelSize: Style.font ? Style.font.caption : 10
                            color: chip.isChipCopied ? root.safeColor : (chip.modelData.online ? root.dim : root.urgent)
                          }
                          Text {
                            text: chip.isChipCopied ? "Copied" : (chip.modelData.name + (chip.modelData.online ? "" : " [off]"))
                            font.family: root.fontFamily
                            font.pixelSize: Style.font ? Style.font.caption : 10
                            font.bold: true
                            color: chip.isChipCopied ? root.safeColor : (chip.modelData.online ? root.foreground : root.dim)
                          }
                        }

                        ToolTip {
                          visible: chipMouse.containsMouse && !runMouse.containsMouse
                          text: (chip.modelData && chip.modelData.name)
                            ? (chip.modelData.name + ":\n• Click to copy: " + chip.modelData.action + "\n• Click 󰐊 to run in terminal")
                            : "Target host"
                          delay: 250
                        }
                      }

                      // Subtle vertical separator
                      Rectangle {
                        width: 1
                        height: Style.space(12)
                        anchors.verticalCenter: parent.verticalCenter
                        color: Util.alpha(root.foreground, 0.2)
                      }

                      // Right target: 1-click Run in terminal
                      MouseArea {
                        id: runMouse
                        width: Style.space(16)
                        height: chip.height
                        hoverEnabled: true
                        cursorShape: Qt.PointingHandCursor
                        onClicked: {
                          if (chip.modelData && chip.modelData.action) {
                            root.runFixAction(chip.modelData.action)
                          }
                        }

                        Rectangle {
                          anchors.fill: parent
                          radius: Style.space(2)
                          color: runMouse.containsMouse ? Util.alpha(root.accent, 0.35) : "transparent"
                          Text {
                            anchors.centerIn: parent
                            text: "󰐊"
                            font.family: root.fontFamily
                            font.pixelSize: Style.font ? Style.font.caption : 9
                            color: runMouse.containsMouse ? root.accent : root.dim
                          }
                        }

                        ToolTip {
                          visible: runMouse.containsMouse
                          text: "Run fix on " + (chip.modelData ? chip.modelData.name : "host") + " in terminal"
                          delay: 200
                        }
                      }
                    }
                  }
                }
              }

              // 3. Reason & CVE summary with clickable primary CVE pill
              RowLayout {
                Layout.fillWidth: true
                spacing: Style.space(6)

                Text {
                  Layout.fillWidth: true
                  text: (itemRow.modelData ? (itemRow.modelData.cve_count + " CVEs • ") : "") + (itemRow.modelData ? itemRow.modelData.reason : "")
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.caption : 10
                  color: itemRow.isTier1 ? root.urgent : root.dim
                  elide: Text.ElideRight
                }

                // Clickable Primary CVE badge if available (opens NVD advisory)
                Rectangle {
                  visible: !!(itemRow.modelData && itemRow.modelData.primary_cve)
                  height: Style.space(18)
                  width: cvePillRow.implicitWidth + Style.space(8)
                  radius: Style.space(3)
                  color: cvePillMouse.containsMouse ? Util.alpha(root.accent, 0.25) : Util.alpha(root.foreground, 0.08)
                  border.color: cvePillMouse.containsMouse ? root.accent : Util.alpha(root.foreground, 0.12)
                  border.width: 1

                  Row {
                    id: cvePillRow
                    anchors.centerIn: parent
                    spacing: Style.space(3)
                    Text {
                      text: root.iconExternal
                      font.family: root.fontFamily
                      font.pixelSize: Style.font ? Style.font.caption : 9
                      color: root.accent
                    }
                    Text {
                      text: itemRow.modelData ? itemRow.modelData.primary_cve : ""
                      font.family: root.fontFamily
                      font.pixelSize: Style.font ? Style.font.caption : 9
                      font.bold: true
                      color: cvePillMouse.containsMouse ? root.accent : root.foreground
                    }
                  }

                  MouseArea {
                    id: cvePillMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    cursorShape: Qt.PointingHandCursor
                    onClicked: {
                      if (itemRow.modelData && itemRow.modelData.nvd_url) {
                        Qt.openUrlExternally(itemRow.modelData.nvd_url)
                      }
                    }
                  }

                  ToolTip {
                    visible: cvePillMouse.containsMouse
                    text: "Open " + (itemRow.modelData ? itemRow.modelData.primary_cve : "") + " on nvd.nist.gov"
                    delay: 200
                  }
                }
              }

              // 4. Action row: Dedicated Remediation Bar (Primary Copy Fix + Run in Terminal)
              RowLayout {
                Layout.fillWidth: true
                spacing: Style.space(8)

                Button {
                  Layout.fillWidth: true
                  text: itemRow.isPkgCopied ? "Copied Fix Command!" : "Copy Fix Command"
                  iconText: itemRow.isPkgCopied ? root.iconCheck : root.iconCopy
                  fontFamily: root.fontFamily
                  fontSize: Style.font ? Style.font.bodySmall : 11
                  iconSize: Style.font ? Style.font.bodySmall : 11
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(4)
                  foreground: itemRow.isPkgCopied ? root.safeColor : root.foreground
                  accent: itemRow.isPkgCopied ? root.safeColor : root.accent
                  bordered: true
                  tooltipText: itemRow.modelData && itemRow.modelData.action
                    ? ("Click to copy: " + itemRow.modelData.action)
                    : "Copy remediation"
                  onClicked: {
                    if (itemRow.modelData && itemRow.modelData.action) {
                      root.copyAction(itemRow.modelData.action, itemRow.pkgTargetId)
                    }
                  }
                }

                Button {
                  text: "Run in Terminal"
                  iconText: root.iconRun
                  fontFamily: root.fontFamily
                  fontSize: Style.font ? Style.font.bodySmall : 11
                  iconSize: Style.font ? Style.font.bodySmall : 11
                  horizontalPadding: Style.space(8)
                  verticalPadding: Style.space(4)
                  foreground: root.accent
                  accent: root.accent
                  bordered: true
                  tooltipText: itemRow.modelData && itemRow.modelData.action
                    ? ("Run remediation in terminal:\n" + itemRow.modelData.action)
                    : "Run remediation in terminal"
                  onClicked: {
                    if (itemRow.modelData && itemRow.modelData.action) {
                      root.runFixAction(itemRow.modelData.action)
                    }
                  }
                }
              }
            }
          }
        }

        // Collapsible Muted Items Drawer
        Rectangle {
          visible: root.mutedItems.length > 0 && !root.isSetupNeeded && !root.isErrorState
          Layout.fillWidth: true
          implicitHeight: mutedCol.implicitHeight + Style.space(12)
          radius: Style.space(6)
          color: Util.alpha(root.foreground, 0.04)
          border.color: Util.alpha(root.foreground, 0.10)
          border.width: 1

          ColumnLayout {
            id: mutedCol
            anchors.fill: parent
            anchors.margins: Style.space(8)
            spacing: Style.space(6)

            MouseArea {
              Layout.fillWidth: true
              implicitHeight: Style.space(22)
              cursorShape: Qt.PointingHandCursor
              onClicked: root.showMuted = !root.showMuted
              RowLayout {
                anchors.fill: parent
                Text {
                  text: root.showMuted ? "󰅀" : "󰅂"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.caption : 10
                  color: root.dim
                }
                Text {
                  text: "󰂛 Muted Packages (" + root.mutedItems.length + ")"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.caption : 10
                  font.bold: true
                  color: root.dim
                }
                Item { Layout.fillWidth: true }
                Text {
                  text: root.showMuted ? "Hide" : "Show"
                  font.family: root.fontFamily
                  font.pixelSize: Style.font ? Style.font.caption : 10
                  color: root.accent
                }
              }
            }

            ListView {
              visible: root.showMuted
              Layout.fillWidth: true
              implicitHeight: Math.min(contentHeight, Style.space(140))
              clip: true
              spacing: Style.space(4)
              model: root.mutedItems
              delegate: Rectangle {
                required property var modelData
                width: parent.width
                implicitHeight: Style.space(32)
                radius: Style.space(4)
                color: Util.alpha(root.foreground, 0.05)
                border.color: Util.alpha(root.foreground, 0.08)
                border.width: 1

                RowLayout {
                  anchors.fill: parent
                  anchors.margins: Style.space(6)
                  spacing: Style.space(6)

                  Text {
                    text: "󰂛 " + (modelData ? modelData.name : "") + " " + (modelData ? modelData.version : "")
                    font.family: root.fontFamily
                    font.pixelSize: Style.font ? Style.font.caption : 10
                    color: root.dim
                    Layout.fillWidth: true
                    elide: Text.ElideRight
                  }

                  Button {
                    text: "Unmute"
                    iconText: root.iconUnmute
                    fontFamily: root.fontFamily
                    fontSize: Style.font ? Style.font.caption : 10
                    horizontalPadding: Style.space(6)
                    verticalPadding: Style.space(2)
                    foreground: root.accent
                    accent: root.accent
                    bordered: true
                    tooltipText: "Restore active alerts for " + (modelData ? modelData.name : "")
                    onClicked: {
                      if (modelData && modelData.name) {
                        root.unmutePackage(modelData.name)
                      }
                    }
                  }
                }
              }
            }
          }
        }

        PanelSeparator {
          Layout.fillWidth: true
          foreground: root.foreground
        }

        // 6. Footer Action Buttons
        RowLayout {
          Layout.fillWidth: true
          spacing: Style.space(8)

          Button {
            Layout.fillWidth: true
            text: "Fleet UI"
            iconText: root.iconExternal
            fontFamily: root.fontFamily
            foreground: root.accent
            accent: root.accent
            bordered: true
            tooltipText: "Open Fleet web dashboard: " + (root.fleetUrl || "")
            onClicked: root.openFleetWeb()
          }

          Button {
            Layout.fillWidth: true
            text: "Terminal Triage"
            iconText: root.iconTerminal
            fontFamily: root.fontFamily
            foreground: root.foreground
            accent: root.accent
            bordered: true
            tooltipText: "Launch full interactive triage report in terminal"
            onClicked: root.launchTriageTerminal()
          }
        }
      }
    }
  }
}
