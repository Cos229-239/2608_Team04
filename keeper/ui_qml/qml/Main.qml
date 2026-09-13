import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtQuick.Dialogs

ApplicationWindow {
    id: window
    width: 1600
    height: 960
    minimumWidth: 1120
    minimumHeight: 700
    visible: true
    color: "#070808"
    title: "Keeper — Executive Control Center"

    readonly property color gold: "#D6A63B"
    readonly property color goldBright: "#F0C45B"
    readonly property color goldDim: "#72551D"
    readonly property color charcoal: "#111313"
    readonly property color panel: "#171919"
    readonly property color panelRaised: "#1D1F1F"
    readonly property color border: "#3B3528"
    readonly property color textPrimary: "#F4F1E9"
    readonly property color textMuted: "#A8A49A"
    readonly property color success: "#59C66D"
    readonly property color warning: "#E6AE36"
    readonly property color danger: "#EA5A53"
    property string searchQuery: ""
    property var selectedRecord: ({})
    property string selectedRunId: ""
    property string projectStateFilter: "ALL"
    property string taskStatusFilter: "ALL"
    property string taskSortKey: "title"
    property bool taskSortAscending: true
    property int taskPage: 0
    readonly property int taskPageSize: 6
    property string findingSeverityFilter: "ALL"
    property string findingStatusFilter: "ALL"
    property string findingRepairFilter: "ALL"
    property string reportAvailabilityFilter: "ALL"
    property string providerHealthFilter: "ALL"
    property string recoveryStatusFilter: "ALL"
    property string pendingConversationText: ""
    property string failedConversationText: ""
    onSearchQueryChanged: taskPage = 0
    onWidthChanged: {
        if (width >= 1360 && narrowAssistantDialog.visible)
            narrowAssistantDialog.close()
    }

    function openAssistant() {
        keeper.navigate("Keeper")
    }
    function keeperConversationItems() {
        var items = (keeper.state.timeline || []).slice()
        if (pendingConversationText.length > 0) {
            items.push({
                "kind": "founder",
                "title": "Founder • Sending",
                "body": pendingConversationText,
                "localState": "sending"
            })
            items.push({
                "kind": "keeper",
                "title": "Keeper",
                "body": keeper.status || "Keeper is working…",
                "localState": "working"
            })
        } else if (failedConversationText.length > 0) {
            items.push({
                "kind": "founder",
                "title": "Not sent • Saved for retry",
                "body": failedConversationText,
                "localState": "failed"
            })
        }
        return items
    }
    function sendKeeperConversation() {
        var outgoing = keeperChatInput.text.trim()
        if (outgoing.length === 0 || keeper.busy)
            return
        keeperChatList.followingNewest = true
        window.failedConversationText = ""
        window.pendingConversationText = outgoing
        keeper.saveConversationDraft(outgoing)
        keeperChatInput.clear()
        keeper.sendAssistantMessage(outgoing)
    }

    Connections {
        target: keeper
        function onOperationFinished(message, successful) {
            if (window.pendingConversationText.length === 0)
                return
            if (!successful)
                window.failedConversationText = window.pendingConversationText
            window.pendingConversationText = ""
        }
    }
    function currentDelegationMode() {
        if (!keeper.state.project) return "ADVISORY"
        var pending = keeper.state.project.approvalCharter || {}
        var active = keeper.state.project.charter || {}
        return String(pending.delegation_mode || active.delegation_mode || "ADVISORY").toUpperCase()
    }
    function delegatedWorkReady() {
        var mode = currentDelegationMode()
        return mode === "DELEGATED" || mode === "FULL_DELEGATION"
    }
    function workflowActionText() {
        if (keeper.busy)
            return "Working…"
        if (keeper.state.project && keeper.state.project.approvalRequired)
            return "Review Required Approval"
        return delegatedWorkReady() ? "Run Approved Work" : "Enable Approved Work"
    }
    function workflowStatusText() {
        if (keeper.busy)
            return "Keeper is working on the current approved stage."
        var stages = keeper.state.workflows || []
        for (var i = 0; i < stages.length; ++i) {
            var status = String(stages[i].status || "READY").toUpperCase()
            if (status !== "READY" && status !== "COMPLETED")
                return window.text(stages[i].title, "Current stage") + " • " + status.replace(/_/g, " ")
        }
        if (stages.length > 0 && stages.every(function(stage) { return String(stage.status || "").toUpperCase() === "COMPLETED" }))
            return "All approved stages are complete."
        return stages.length > 0 ? "Ready to start the next approved stage." : "Approve a project charter to create a workflow."
    }
    function handleWorkflowAction() {
        if (keeper.state.project && keeper.state.project.approvalRequired)
            charterDialog.open()
        else if (!delegatedWorkReady())
            delegatedModeDialog.open()
        else
            keeper.runDelegatedCompletion()
    }
    function pageIndex(name) {
        var pages = keeper.state.navigation || []
        for (var i = 0; i < pages.length; ++i)
            if (pages[i] === name) return i
        return 0
    }
    function rows(name) { return keeper.state[name] || [] }
    function filtered(values) {
        var source = values || []
        var query = searchQuery.trim().toLowerCase()
        if (!query) return source
        return source.filter(function(item) {
            return JSON.stringify(item).toLowerCase().indexOf(query) >= 0
        })
    }
    function openSearchResults() {
        var query = searchQuery.trim().toLowerCase()
        if (!query) return
        var destinations = [
            ["recovery", "Recovery"], ["uncertain", "Recovery"],
            ["provider", "Providers"], ["task", "Tasks"],
            ["workflow", "Workflows"], ["evidence", "Evidence"],
            ["review", "Reviews"], ["finding", "Findings"],
            ["authorization", "Authorizations"], ["report", "Reports"],
            ["repository", "Repositories"], ["project", "Projects"]
        ]
        for (var i = 0; i < destinations.length; ++i) {
            if (query.indexOf(destinations[i][0]) >= 0) {
                keeper.navigate(destinations[i][1])
                return
            }
        }
        var collections = [
            [keeper.state.project ? keeper.state.project.catalog : [], "Projects"],
            [keeper.state.workflows || [], "Workflows"],
            [keeper.state.tasks || [], "Tasks"],
            [keeper.state.evidence || [], "Evidence"],
            [keeper.state.evidenceReferences || [], "Evidence"],
            [keeper.state.runs || [], "Reports"]
        ]
        for (var j = 0; j < collections.length; ++j) {
            if (filtered(collections[j][0]).length > 0) {
                keeper.navigate(collections[j][1])
                return
            }
        }
    }
    function friendlyRecord(record) {
        var value = record || {}
        var preferred = ["title", "name", "status", "state", "stage", "role",
                         "objective", "summary", "reason", "detail", "capability",
                         "task_id", "run_id", "project_id", "branch", "category"]
        var seen = ({})
        var lines = []
        function add(key) {
            if (seen[key] || value[key] === undefined || value[key] === null || value[key] === "") return
            seen[key] = true
            var label = key.replace(/_/g, " ")
            label = label.charAt(0).toUpperCase() + label.slice(1)
            var content = value[key]
            if (typeof content === "object") content = JSON.stringify(content, null, 2)
            lines.push(label + ": " + content)
        }
        for (var i = 0; i < preferred.length; ++i) add(preferred[i])
        Object.keys(value).forEach(add)
        return lines.length > 0 ? lines.join("\n\n") : "No additional details are available."
    }
    function filteredProjects() {
        var source = filtered(keeper.state.project ? keeper.state.project.catalog : [])
        if (projectStateFilter === "ALL") return source
        return source.filter(function(item) {
            return String(item.state || item.status || "UNKNOWN").toUpperCase() === projectStateFilter
        })
    }
    function taskFilteredRows() {
        var source = filtered(keeper.state.tasks || []).filter(function(item) {
            return taskStatusFilter === "ALL" || String(item.status || "INTAKE").toUpperCase() === taskStatusFilter
        })
        source = source.slice().sort(function(left, right) {
            var a = String(left[taskSortKey] || "").toLowerCase()
            var b = String(right[taskSortKey] || "").toLowerCase()
            return (a < b ? -1 : (a > b ? 1 : 0)) * (taskSortAscending ? 1 : -1)
        })
        return source
    }
    function taskPageCount() {
        return Math.max(1, Math.ceil(taskFilteredRows().length / taskPageSize))
    }
    function taskSafePage() {
        return Math.min(taskPage, taskPageCount() - 1)
    }
    function taskPageRows() {
        var source = taskFilteredRows()
        var safePage = taskSafePage()
        return source.slice(safePage * taskPageSize, (safePage + 1) * taskPageSize)
    }
    function filteredFindings() {
        return filtered(keeper.state.findings || []).filter(function(item) {
            var severity = String(item.severity || "UNKNOWN").toUpperCase()
            var status = String(item.status || "UNKNOWN").toUpperCase()
            var repaired = status === "REPAIRED" || status === "VERIFIED" || !!item.repaired_at
            return (findingSeverityFilter === "ALL" || severity === findingSeverityFilter)
                && (findingStatusFilter === "ALL" || status === findingStatusFilter)
                && (findingRepairFilter === "ALL" || (findingRepairFilter === "REPAIRED") === repaired)
        })
    }
    function reportRows() {
        return filtered(keeper.state.runs || []).filter(function(item) {
            var exportable = !!item.evidence_manifest_digest
            return reportAvailabilityFilter === "ALL"
                || (reportAvailabilityFilter === "EXPORTABLE" && exportable)
                || (reportAvailabilityFilter === "PENDING" && !exportable)
        })
    }
    function providerRows() {
        return filtered(keeper.state.providers || []).filter(function(item) {
            var ready = String(item.health || "UNAVAILABLE").toUpperCase() === "READY"
            return providerHealthFilter === "ALL"
                || (providerHealthFilter === "READY" && ready)
                || (providerHealthFilter === "NOT READY" && !ready)
        })
    }
    function recoveryRows() {
        return filtered(keeper.state.recoveries || []).filter(function(item) {
            var uncertain = String(item.status || "UNKNOWN").toUpperCase() === "UNCERTAIN"
            return recoveryStatusFilter === "ALL"
                || (recoveryStatusFilter === "UNCERTAIN" && uncertain)
                || (recoveryStatusFilter === "RESUMABLE" && !uncertain
                    && (item.recovery_action === "resume" || item.recovery_action === "retry"))
        })
    }
    function text(value, fallback) {
        if (value === undefined || value === null || value === "") return fallback || "—"
        return String(value)
    }
    function statusColor(value) {
        var state = String(value || "").toUpperCase()
        if (["READY", "ACTIVE", "COMPLETED", "VALIDATED", "ACCEPTED", "AVAILABLE", "HEALTHY"].indexOf(state) >= 0) return success
        if (["FAILED", "REJECTED", "REVOKED", "BLOCKED", "CANCELLED", "UNAVAILABLE"].indexOf(state) >= 0) return danger
        return warning
    }

    component GoldButton: Button {
        id: control
        implicitHeight: 40
        leftPadding: 18; rightPadding: 18
        font.pixelSize: 14; font.weight: Font.DemiBold
        contentItem: Text {
            text: control.text
            color: control.enabled ? "#090909" : "#77746C"
            font: control.font
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 5
            color: control.enabled ? (control.down ? "#B88625" : gold) : "#292A29"
            border.color: control.enabled ? goldBright : "#444444"
        }
        ToolTip.visible: hovered && ToolTip.text.length > 0
        ToolTip.delay: 350
    }

    component QuietButton: Button {
        id: control
        implicitHeight: 38
        leftPadding: 14; rightPadding: 14
        font.pixelSize: 13
        contentItem: Text {
            text: control.text
            color: control.enabled ? textPrimary : "#6D6D69"
            font: control.font
            horizontalAlignment: Text.AlignHCenter
            verticalAlignment: Text.AlignVCenter
        }
        background: Rectangle {
            radius: 5
            color: control.down ? "#2A2925" : "#1B1D1D"
            border.color: control.hovered ? goldDim : "#393B3A"
        }
        ToolTip.visible: hovered && ToolTip.text.length > 0
        ToolTip.delay: 350
    }

    component KPanel: Rectangle {
        default property alias content: body.data
        color: panel
        radius: 7
        clip: true
        border.width: 1
        border.color: border
        implicitHeight: body.implicitHeight + 32
        ColumnLayout {
            id: body
            anchors.fill: parent
            anchors.margins: 16
            spacing: 12
        }
    }

    component TrustItem: ColumnLayout {
        property string label: ""
        property string detail: ""
        spacing: 2
        Text {
            text: parent.label
            color: goldBright
            font.pixelSize: 10
            font.weight: Font.Bold
            font.letterSpacing: 0.45
        }
        Text {
            text: parent.detail
            color: textPrimary
            font.pixelSize: 10
        }
    }

    component MetricCard: Rectangle {
        id: metricCard
        property string label: ""
        property string value: "0"
        property string route: "Overview"
        Layout.fillWidth: true
        Layout.preferredHeight: 108
        radius: 7
        color: metricMouse.containsMouse ? "#1C1F1E" : panel
        border.width: 1
        border.color: metricMouse.containsMouse ? goldDim : border

        Rectangle {
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            width: 4
            radius: 2
            color: gold
        }
        ColumnLayout {
            anchors.fill: parent
            anchors.leftMargin: 20
            anchors.rightMargin: 16
            anchors.topMargin: 14
            anchors.bottomMargin: 14
            spacing: 5
            Text {
                text: metricCard.label.toUpperCase()
                color: goldBright
                font.pixelSize: 11
                font.weight: Font.Bold
                font.letterSpacing: 0.55
            }
            Text {
                text: metricCard.value
                color: textPrimary
                font.pixelSize: 32
                font.weight: Font.DemiBold
            }
            Text {
                text: "Open " + metricCard.label.toLowerCase() + "  →"
                color: textMuted
                font.pixelSize: 10
            }
        }
        MouseArea {
            id: metricMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: keeper.navigate(metricCard.route)
        }
    }

    component SectionTitle: Text {
        color: goldBright
        font.pixelSize: 13
        font.weight: Font.Bold
        font.letterSpacing: 0.5
        textFormat: Text.PlainText
    }

    component BodyText: Text {
        color: textPrimary
        font.pixelSize: 14
        wrapMode: Text.Wrap
        textFormat: Text.PlainText
    }

    component MutedText: Text {
        color: textMuted
        font.pixelSize: 12
        wrapMode: Text.Wrap
        textFormat: Text.PlainText
    }

    component StatusPill: Rectangle {
        property string value: "UNKNOWN"
        implicitWidth: label.implicitWidth + 18
        implicitHeight: 26
        radius: 4
        color: Qt.rgba(statusColor(value).r, statusColor(value).g, statusColor(value).b, 0.13)
        border.color: statusColor(value)
        Text { id: label; anchors.centerIn: parent; text: parent.value; color: statusColor(parent.value); font.pixelSize: 11; font.weight: Font.DemiBold }
    }

    component EmptyState: Item {
        id: emptyRoot
        property string title: "Nothing here yet"
        property string detail: "Keeper will show durable state here when it becomes available."
        implicitHeight: 180
        Column {
            width: Math.min(460, Math.max(120, emptyRoot.width - 24))
            anchors.centerIn: parent
            spacing: 10
            Text { width: parent.width; horizontalAlignment: Text.AlignHCenter; text: "◇"; color: gold; font.pixelSize: 34 }
            Text { width: parent.width; horizontalAlignment: Text.AlignHCenter; text: emptyRoot.title; color: textPrimary; font.pixelSize: 18; font.weight: Font.DemiBold; wrapMode: Text.Wrap }
            Text { width: parent.width; horizontalAlignment: Text.AlignHCenter; text: emptyRoot.detail; color: textMuted; font.pixelSize: 13; wrapMode: Text.Wrap }
        }
    }

    component PageHeader: RowLayout {
        id: pageHeader
        property string title: ""
        property string subtitle: ""
        property string actionText: ""
        property bool actionEnabled: true
        signal action()
        Layout.fillWidth: true
        ColumnLayout {
            Layout.fillWidth: true
            Layout.minimumWidth: 0
            spacing: 3
            Text { Layout.fillWidth: true; text: pageHeader.title; color: textPrimary; font.pixelSize: 28; font.weight: Font.DemiBold; elide: Text.ElideRight }
            MutedText { Layout.fillWidth: true; text: pageHeader.subtitle; elide: Text.ElideRight }
        }
        GoldButton {
            objectName: "pageAction-" + pageHeader.title
            visible: pageHeader.actionText.length > 0
            text: pageHeader.actionText
            enabled: pageHeader.actionEnabled
            onClicked: pageHeader.action()
        }
    }

    component RecordRow: Rectangle {
        id: recordRow
        property string title: ""
        property string subtitle: ""
        property string state: ""
        width: ListView.view ? ListView.view.width : 600
        height: 68
        color: index % 2 ? "#141616" : "#101212"
        border.color: "#292B2A"
        RowLayout {
            anchors.fill: parent; anchors.leftMargin: 16; anchors.rightMargin: 16
            Rectangle { Layout.preferredWidth: 4; Layout.preferredHeight: 34; radius: 2; color: statusColor(parent.parent.state) }
            ColumnLayout {
                Layout.fillWidth: true; Layout.minimumWidth: 0; spacing: 3
                BodyText { Layout.fillWidth: true; text: recordRow.title; font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 }
                MutedText { Layout.fillWidth: true; text: recordRow.subtitle; elide: Text.ElideRight; maximumLineCount: 1 }
            }
            StatusPill { visible: parent.parent.state.length > 0; value: parent.parent.state }
        }
    }

    Rectangle {
        anchors.fill: parent
        color: "#070808"
        gradient: Gradient {
            GradientStop { position: 0; color: "#111312" }
            GradientStop { position: 0.65; color: "#090A0A" }
            GradientStop { position: 1; color: "#050606" }
        }
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            id: sidebar
            Layout.preferredWidth: window.width < 1300 ? 210 : 248
            Layout.fillHeight: true
            color: "#0C0E0D"
            border.color: goldDim
            ColumnLayout {
                anchors.fill: parent
                anchors.margins: 14
                spacing: 8
                Image {
                    Layout.alignment: Qt.AlignHCenter
                    source: keeperIcon
                    sourceSize.width: 108; sourceSize.height: 108
                    fillMode: Image.PreserveAspectFit
                    Layout.preferredWidth: 118; Layout.preferredHeight: 118
                }
                Text { Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter; text: "KEEPER"; color: goldBright; font.family: "Georgia"; font.pixelSize: 22; font.weight: Font.DemiBold; font.letterSpacing: 2; clip: true }
                MutedText { Layout.fillWidth: true; horizontalAlignment: Text.AlignHCenter; text: "EXECUTIVE CONTROL CENTER"; font.pixelSize: 8; color: gold; elide: Text.ElideRight; clip: true }
                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border; Layout.topMargin: 8; Layout.bottomMargin: 4 }
                ScrollView {
                    Layout.fillWidth: true; Layout.fillHeight: true
                    clip: true
                    ColumnLayout {
                        width: parent.width
                        spacing: 3
                        Repeater {
                            model: keeper.state.navigation || []
                            delegate: Button {
                                id: navButton
                                objectName: "nav" + modelData.replace(/ /g, "")
                                required property string modelData
                                Layout.fillWidth: true
                                implicitHeight: 39
                                text: modelData
                                checkable: true
                                checked: keeper.currentPage === modelData
                                onClicked: keeper.navigate(modelData)
                                contentItem: Text { text: navButton.text; color: navButton.checked ? goldBright : textPrimary; font.pixelSize: 13; font.weight: navButton.checked ? Font.DemiBold : Font.Normal; verticalAlignment: Text.AlignVCenter; leftPadding: 14 }
                                background: Rectangle { radius: 5; color: navButton.checked ? "#382B0F" : (navButton.hovered ? "#191B1A" : "transparent"); border.color: navButton.checked ? goldDim : "transparent" }
                            }
                        }
                    }
                }
                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                RowLayout {
                    Layout.fillWidth: true
                    Rectangle { Layout.preferredWidth: 10; Layout.preferredHeight: 10; radius: 5; color: statusColor(keeper.state.diagnostics ? keeper.state.diagnostics.authorityStatus : "UNAVAILABLE") }
                    ColumnLayout {
                        Layout.fillWidth: true; spacing: 2
                        BodyText { text: "Keeper " + String(keeper.state.version || ""); font.pixelSize: 12 }
                        MutedText { text: String(keeper.state.environment || "NOT CONFIGURED"); font.pixelSize: 10 }
                    }
                }
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0
            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 78
                color: "#0D0F0E"
                border.color: "#292B29"
                RowLayout {
                    anchors.fill: parent; anchors.leftMargin: 24; anchors.rightMargin: 24
                    ColumnLayout {
                        spacing: 1
                        Text { text: keeper.currentPage; color: textPrimary; font.pixelSize: 19; font.weight: Font.DemiBold }
                        MutedText { text: "Founder-governed local workspace"; font.pixelSize: 10 }
                    }
                    Item { Layout.fillWidth: true }
                    RowLayout {
                        visible: window.width >= 1430
                        spacing: 22
                        TrustItem { label: "FOUNDER FIRST"; detail: "Explicit authority" }
                        TrustItem { label: "AUTHORITY READY"; detail: "Every action verified" }
                        TrustItem { label: "AUDIT & RECEIPTS"; detail: "Nothing hidden" }
                    }
                    Rectangle { visible: window.width >= 1430; Layout.preferredWidth: 1; Layout.preferredHeight: 34; color: border }
                    TextField {
                        objectName: "globalSearch"
                        Layout.preferredWidth: window.width >= 1500 ? 300 : 220
                        Layout.minimumWidth: 160
                        placeholderText: "Search projects, workflows, evidence…"
                        color: textPrimary
                        placeholderTextColor: "#777777"
                        onTextChanged: window.searchQuery = text
                        onAccepted: window.openSearchResults()
                        background: Rectangle { color: "#121414"; radius: 5; border.color: parent.activeFocus ? gold : "#3A3C3B" }
                    }
                    QuietButton { objectName: "refreshButton"; text: "Refresh"; onClicked: keeper.refresh() }
                    Rectangle { Layout.preferredWidth: 1; Layout.preferredHeight: 34; color: border }
                    ColumnLayout {
                        spacing: 0
                        BodyText { text: "Founder"; font.weight: Font.DemiBold; font.pixelSize: 13 }
                        MutedText { text: "Local session"; font.pixelSize: 10 }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0
                StackLayout {
                    id: pages
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: pageIndex(keeper.currentPage)

                    Flickable {
                        contentWidth: width; contentHeight: overviewColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: overviewColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Overview"; subtitle: "Tell Keeper what you want to build. Keeper handles the approved project from there."; actionText: "+ Talk to Keeper"; onAction: { keeper.startNewProject(); window.openAssistant() } }
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 112
                                radius: 8
                                color: "#151817"
                                border.width: 1
                                border.color: goldDim
                                Rectangle { anchors.left: parent.left; anchors.top: parent.top; anchors.bottom: parent.bottom; width: 5; radius: 2; color: gold }
                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 24
                                    anchors.rightMargin: 22
                                    anchors.topMargin: 18
                                    anchors.bottomMargin: 18
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 5
                                        Text {
                                            Layout.fillWidth: true
                                            text: "Welcome, Founder"
                                            color: textPrimary
                                            font.pixelSize: 22
                                            font.weight: Font.DemiBold
                                        }
                                        MutedText {
                                            Layout.fillWidth: true
                                            text: window.text(keeper.state.project ? keeper.state.project.title : "", "No active Keeper project")
                                            elide: Text.ElideMiddle
                                            maximumLineCount: 2
                                            font.pixelSize: 13
                                        }
                                        RowLayout {
                                            spacing: 8
                                            Rectangle { Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4; color: statusColor(keeper.state.diagnostics ? keeper.state.diagnostics.authorityStatus : "UNAVAILABLE") }
                                            Text { text: "KeeperAuthority " + window.text(keeper.state.diagnostics ? keeper.state.diagnostics.authorityStatus : "", "UNAVAILABLE").toUpperCase(); color: statusColor(keeper.state.diagnostics ? keeper.state.diagnostics.authorityStatus : "UNAVAILABLE"); font.pixelSize: 11; font.weight: Font.DemiBold }
                                            Text { text: "•"; color: textMuted; font.pixelSize: 11 }
                                            MutedText { text: (keeper.state.counts ? keeper.state.counts.uncertain : 0) + " uncertain outcome(s) preserved"; font.pixelSize: 11 }
                                        }
                                    }
                                    ColumnLayout {
                                        visible: window.width >= 1300
                                        Layout.alignment: Qt.AlignVCenter | Qt.AlignRight
                                        spacing: 3
                                        SectionTitle { text: "FOUNDER MODE" }
                                        MutedText { text: "Authority is never delegated by the UI"; horizontalAlignment: Text.AlignRight }
                                    }
                                }
                            }
                            RowLayout { Layout.fillWidth: true; BodyText { text: "Active project" } ComboBox { id: projectSelector; Layout.fillWidth: true; Layout.minimumWidth: 180; Layout.maximumWidth: 520; model: keeper.state.project ? keeper.state.project.catalog || [] : []; textRole: "title"; valueRole: "project_id"; onActivated: keeper.selectProject(currentValue); contentItem: Text { leftPadding: 12; rightPadding: 12; text: projectSelector.displayText || "No active Keeper project"; color: textPrimary; verticalAlignment: Text.AlignVCenter; elide: Text.ElideMiddle; clip: true } background: Rectangle { color: "#101212"; border.color: projectSelector.activeFocus ? gold : "#393B3A"; radius: 4 } } QuietButton { text: "Talk to Keeper"; onClicked: window.openAssistant() } Item { Layout.fillWidth: true } }
                            RowLayout {
                                Layout.fillWidth: true; spacing: 12
                                Repeater {
                                    model: [
                                        ["Projects", keeper.state.counts ? keeper.state.counts.projects : 0, "Projects"],
                                        ["Workflows", keeper.state.counts ? keeper.state.counts.workflows : 0, "Workflows"],
                                        ["Approvals", keeper.state.counts ? keeper.state.counts.approvals : 0, "Authorizations"],
                                        ["Providers", keeper.state.counts ? keeper.state.counts.providers : 0, "Providers"]
                                    ]
                                    MetricCard { label: modelData[0]; value: String(modelData[1]); route: modelData[2] }
                                }
                            }
                            RowLayout {
                                Layout.fillWidth: true; spacing: 14
                                KPanel {
                                    Layout.fillWidth: true; Layout.preferredHeight: 320
                                    SectionTitle { text: "CURRENT PROJECT" }
                                    BodyText { Layout.fillWidth: true; text: window.text(keeper.state.project ? keeper.state.project.title : "", "No active Keeper project"); font.pixelSize: 20; font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 }
                                    StatusPill { value: window.text(keeper.state.project ? keeper.state.project.status : "", "NOT_STARTED") }
                                    MutedText { text: keeper.state.project && keeper.state.project.charterRevision ? "Founder-approved charter revision " + keeper.state.project.charterRevision : "Describe a project in Keeper Assistant to create a proposed charter."; Layout.fillWidth: true }
                                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: "#2B2D2C" }
                                    MutedText { text: "Every launch remains bound to the active charter and verified provider identity."; Layout.fillWidth: true }
                                    Item { Layout.fillHeight: true }
                                    GoldButton { text: keeper.state.project && keeper.state.project.approvalRequired ? "Review Founder Approval" : "Continue with Keeper"; onClicked: { if (keeper.state.project && keeper.state.project.approvalRequired) charterDialog.open(); else window.openAssistant() } }
                                }
                                KPanel {
                                    Layout.fillWidth: true; Layout.preferredHeight: 320
                                    SectionTitle { text: "SYSTEM INTEGRITY" }
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        Layout.fillHeight: true
                                        spacing: 3
                                        Repeater {
                                            model: keeper.state.rightRail || []
                                            RowLayout {
                                                Layout.fillWidth: true
                                                Layout.minimumHeight: 16
                                                Rectangle { Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4; color: statusColor(modelData[1]) }
                                                MutedText { text: modelData[0]; Layout.preferredWidth: 150; elide: Text.ElideRight; maximumLineCount: 1 }
                                                BodyText { Layout.fillWidth: true; Layout.minimumWidth: 0; text: modelData[1]; font.pixelSize: 12; horizontalAlignment: Text.AlignRight; elide: Text.ElideMiddle; maximumLineCount: 1 }
                                            }
                                        }
                                    }
                                }
                            }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 220
                                SectionTitle { text: "RECENT DURABLE ACTIVITY" }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                                    model: (keeper.state.timeline || []).slice(-4)
                                    delegate: RecordRow { title: modelData.title; subtitle: modelData.body; state: modelData.state }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No project activity yet"; detail: "Describe your first project to begin a durable Keeper conversation." }
                                }
                            }
                        }
                    }

                    Item {
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 24
                            spacing: 16
                            PageHeader {
                                title: "Keeper"
                                subtitle: "Talk naturally about what you want. Keeper develops the idea and carries out the approved project."
                                actionText: "+ New Project"
                                onAction: {
                                    keeper.startNewProject()
                                    keeperChatInput.forceActiveFocus()
                                }
                            }
                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 10
                                BodyText { text: "Primary agent"; font.weight: Font.DemiBold }
                                ComboBox {
                                    id: conversationProviderSelector
                                    objectName: "conversationProviderSelector"
                                    Layout.preferredWidth: 280
                                    model: keeper.state.settings ? keeper.state.settings.conversationProviders || [] : []
                                    textRole: "name"
                                    valueRole: "provider_id"
                                    currentIndex: {
                                        var selected = keeper.state.settings ? keeper.state.settings.conversationProvider || "" : ""
                                        for (var i = 0; i < model.length; ++i)
                                            if (model[i].provider_id === selected) return i
                                        return model.length > 0 ? 0 : -1
                                    }
                                    enabled: model.length > 0 && !keeper.busy
                                    onActivated: keeper.selectConversationProvider(currentValue)
                                }
                                StatusPill {
                                    value: conversationProviderSelector.currentIndex >= 0 ? "READY" : "UNAVAILABLE"
                                }
                                MutedText {
                                    Layout.fillWidth: true
                                    text: conversationProviderSelector.currentIndex >= 0
                                        ? "Keeper will prefer this agent for project work and use another approved agent for independent review."
                                        : "No Authority-qualified provider is ready."
                                    wrapMode: Text.WordWrap
                                }
                            }
                            KPanel {
                                Layout.fillWidth: true
                                Layout.fillHeight: true
                                SectionTitle { text: "CONVERSATION" }
                                RowLayout {
                                    Layout.fillWidth: true
                                    MutedText {
                                        Layout.fillWidth: true
                                        text: keeperChatList.followingNewest
                                            ? "Showing the newest message"
                                            : "You are viewing an earlier part of the conversation"
                                    }
                                    QuietButton {
                                        visible: !keeperChatList.followingNewest
                                        text: "Jump to newest"
                                        onClicked: {
                                            keeperChatList.followingNewest = true
                                            keeperChatList.positionViewAtEnd()
                                        }
                                    }
                                }
                                ListView {
                                    id: keeperChatList
                                    objectName: "keeperChatList"
                                    property bool followingNewest: true
                                    Layout.fillWidth: true
                                    Layout.fillHeight: true
                                    clip: true
                                    spacing: 10
                                    boundsBehavior: Flickable.StopAtBounds
                                    model: window.keeperConversationItems()
                                    ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }
                                    onCountChanged: {
                                        if (followingNewest)
                                            Qt.callLater(function() { keeperChatList.positionViewAtEnd() })
                                    }
                                    onContentYChanged: {
                                        if (moving && !atYEnd)
                                            followingNewest = false
                                        else if (atYEnd)
                                            followingNewest = true
                                    }
                                    Component.onCompleted: Qt.callLater(function() { keeperChatList.positionViewAtEnd() })
                                    delegate: Rectangle {
                                        required property var modelData
                                        width: Math.min(keeperChatList.width * 0.84, 860)
                                        x: modelData.kind === "founder" ? keeperChatList.width - width - 12 : 12
                                        implicitHeight: keeperChatMessage.implicitHeight + 54
                                        radius: 9
                                        color: modelData.kind === "founder" ? "#252626" : "#151817"
                                        border.color: modelData.kind === "founder" ? "#4B4B48" : goldDim
                                        ColumnLayout {
                                            anchors.fill: parent
                                            anchors.margins: 14
                                            spacing: 5
                                            Text {
                                                Layout.fillWidth: true
                                                text: window.text(modelData.title, modelData.kind === "founder" ? "Founder" : "Keeper")
                                                color: modelData.kind === "founder" ? textMuted : goldBright
                                                font.pixelSize: 11
                                                font.weight: Font.Bold
                                            }
                                            Text {
                                                id: keeperChatMessage
                                                Layout.fillWidth: true
                                                text: window.text(modelData.body, "")
                                                color: textPrimary
                                                font.pixelSize: 14
                                                wrapMode: Text.Wrap
                                                textFormat: Text.PlainText
                                            }
                                        }
                                    }
                                    EmptyState {
                                        anchors.fill: parent
                                        visible: parent.count === 0
                                        title: "What do you want to make?"
                                        detail: "Describe it in your own words. Keeper will develop the idea with you and prepare the project."
                                    }
                                }
                                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                                RowLayout {
                                    Layout.fillWidth: true
                                    visible: window.failedConversationText.length > 0
                                    spacing: 10
                                    MutedText {
                                        Layout.fillWidth: true
                                        text: "Keeper could not finish that request. Your message is saved."
                                        color: warning
                                    }
                                    QuietButton {
                                        text: "Edit & retry"
                                        onClicked: {
                                            keeperChatInput.text = window.failedConversationText
                                            window.failedConversationText = ""
                                            keeperChatInput.forceActiveFocus()
                                        }
                                    }
                                }
                                RowLayout {
                                    Layout.fillWidth: true
                                    spacing: 10
                                    TextArea {
                                        id: keeperChatInput
                                        objectName: "keeperChatInput"
                                        Layout.fillWidth: true
                                        Layout.preferredHeight: 92
                                        placeholderText: "Tell Keeper what you want to build or change…"
                                        color: textPrimary
                                        placeholderTextColor: "#777777"
                                        wrapMode: TextEdit.Wrap
                                        background: Rectangle { color: "#111313"; border.color: parent.activeFocus ? gold : "#3A3C3A"; radius: 6 }
                                        text: keeper.conversationDraft
                                        onTextChanged: draftSaveTimer.restart()
                                        Keys.onPressed: function(event) {
                                            if ((event.modifiers & Qt.ControlModifier)
                                                    && (event.key === Qt.Key_Return
                                                        || event.key === Qt.Key_Enter)) {
                                                window.sendKeeperConversation()
                                                event.accepted = true
                                            }
                                        }
                                        Timer {
                                            id: draftSaveTimer
                                            interval: 400
                                            repeat: false
                                            onTriggered: {
                                                if (window.pendingConversationText.length === 0)
                                                    keeper.saveConversationDraft(keeperChatInput.text)
                                            }
                                        }
                                    }
                                    ColumnLayout {
                                        spacing: 5
                                        GoldButton {
                                            objectName: "keeperChatSend"
                                            text: keeper.busy ? "Working…" : "Send"
                                            enabled: keeperChatInput.text.trim().length > 0 && !keeper.busy
                                            onClicked: window.sendKeeperConversation()
                                        }
                                        MutedText { text: "Ctrl+Enter to send\nDraft saved locally"; font.pixelSize: 10 }
                                    }
                                }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: projectColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: projectColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Projects & Charters"; subtitle: "Founder intent, current charter, and execution boundaries."; actionText: "+ New Project"; onAction: { keeper.startNewProject(); window.openAssistant() } }
                            RowLayout { Layout.fillWidth: true; Item { Layout.fillWidth: true } BodyText { text: "Project state" } ComboBox { id: projectStateSelector; Layout.preferredWidth: 230; model: ["ALL", "INTAKE", "CLARIFICATION_REQUIRED", "CHARTER_DRAFT", "AWAITING_CHARTER_APPROVAL", "ACTIVE", "PLANNING", "EXECUTING", "REVIEWING", "BLOCKED", "PAUSED", "WAITING_FOR_PROVIDER", "WAITING_FOR_USAGE_RESET", "WAITING_FOR_FOUNDER", "WAITING_FOR_CREDENTIAL", "WAITING_FOR_EXTERNAL_SYSTEM", "COMPLETED", "CANCELED", "FAILED", "RECOVERY_REQUIRED", "UNKNOWN"]; onActivated: window.projectStateFilter = currentText } }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 230
                                SectionTitle { text: "KEEPER PROJECTS" }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; clip: true
                                    model: filteredProjects()
                                    delegate: Rectangle {
                                        width: ListView.view.width; height: 64; color: mouse.containsMouse ? "#20211F" : "transparent"; border.color: "#30322F"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; BodyText { Layout.fillWidth: true; text: window.text(modelData.title, modelData.project_id); font.weight: Font.DemiBold } StatusPill { value: window.text(modelData.state, "UNKNOWN") } }
                                        MouseArea { id: mouse; anchors.fill: parent; hoverEnabled: true; onClicked: keeper.selectProject(modelData.project_id) }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No Keeper project yet"; detail: "Use Keeper Assistant to describe an outcome. Keeper will draft a charter for review." }
                                }
                            }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 330
                                SectionTitle { text: "CURRENT CHARTER" }
                                BodyText { text: window.text(keeper.state.project ? keeper.state.project.title : "", "No current charter"); font.pixelSize: 21; font.weight: Font.DemiBold }
                                MutedText { text: keeper.state.project && keeper.state.project.charterRevision ? "Revision " + keeper.state.project.charterRevision : "A charter has not been approved." }
                                BodyText { Layout.fillWidth: true; text: keeper.state.project && keeper.state.project.charter && keeper.state.project.charter.objective ? keeper.state.project.charter.objective : "The approved scope, exclusions, constraints, providers, and delegated envelope appear here." }
                                Item { Layout.fillHeight: true }
                                RowLayout { QuietButton { text: "Discuss / Revise"; onClicked: window.openAssistant() } GoldButton { objectName: "approveCharterButton"; visible: keeper.state.project && keeper.state.project.approvalRequired; text: "Review & Approve Charter"; onClicked: charterDialog.open() } }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: repositoryColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: repositoryColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Repositories"; subtitle: "Protected originals and isolated execution workspaces."; actionText: "+ Add Repository"; onAction: addRepositoryDialog.open() }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 460; SectionTitle { text: "REGISTERED REPOSITORIES" } ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.projects || []); clip: true; delegate: RecordRow { title: text(modelData.name, modelData.id); subtitle: "Branch " + text(modelData.branch, "unknown") + " • protected original: " + text(modelData.protected_original, "true"); state: modelData.dirty ? "DIRTY" : "READY" } EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No repository configured"; detail: "Add a local Git repository. Keeper keeps its original protected and performs work in isolated reservations." } } }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: workflowColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: workflowColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Workflows"; subtitle: "Plan, implementation, independent review, repair, and verification."; actionText: window.workflowActionText(); actionEnabled: !!(keeper.state.project && keeper.state.project.id) && !keeper.busy; onAction: window.handleWorkflowAction() }
                            KPanel {
                                Layout.fillWidth: true
                                visible: !!(keeper.state.project && keeper.state.project.id) && !window.delegatedWorkReady()
                                SectionTitle { text: "APPROVED WORK IS NOT ENABLED" }
                                BodyText { Layout.fillWidth: true; text: "This project is in Advisory mode. Keeper can show the plan, but it cannot run a provider until you approve Delegated mode." }
                                MutedText { Layout.fillWidth: true; text: "Choose Enable Approved Work above. Keeper will prepare the one required revision and clearly show the Founder approval step." }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 520; SectionTitle { text: "ACTIVE WORKFLOW" } MutedText { Layout.fillWidth: true; text: window.workflowStatusText(); wrapMode: Text.WordWrap } ListView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 10; model: filtered(keeper.state.workflows || []); delegate: Rectangle { width: ListView.view.width; height: 82; radius: 6; color: workflowMouse.containsMouse ? "#1B1D1C" : "#121414"; border.color: statusColor(modelData.status); RowLayout { anchors.fill: parent; anchors.margins: 14; Rectangle { Layout.preferredWidth: 42; Layout.preferredHeight: 42; radius: 21; color: "#2D2513"; Text { anchors.centerIn: parent; text: index + 1; color: goldBright; font.pixelSize: 18 } } ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.title, "Work item"); font.weight: Font.DemiBold; elide: Text.ElideRight; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: "Role: " + window.text(modelData.role, "unassigned"); elide: Text.ElideRight; maximumLineCount: 1 } } StatusPill { value: window.text(modelData.status, "PROPOSED") } QuietButton { text: "Stage details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } } MouseArea { id: workflowMouse; anchors.fill: parent; hoverEnabled: true; z: -1; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } } EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No workflow planned"; detail: "Approve the proposed charter once. Keeper will then plan and advance routine work inside its delegated envelope." } } }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: taskColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: taskColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Tasks"; subtitle: "Keeper creates these from your approved conversation. Manual task entry is an advanced fallback."; actionText: "Advanced: Add Task"; actionEnabled: (keeper.state.projects || []).length > 0; onAction: taskDialog.open() }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 520
                                SectionTitle { text: "TASK QUEUE" }
                                RowLayout { Layout.fillWidth: true
                                    BodyText { text: "Status" }
                                    ComboBox { id: taskStatusSelector; Layout.preferredWidth: 190; model: ["ALL", "INTAKE", "BACKLOG", "READY", "BUILDING", "SELF_VERIFYING", "INDEPENDENT_AUDIT", "REPAIRING", "FINAL_VERIFY", "APPROVED", "COMPLETED", "BLOCKED", "FAILED", "PAUSED", "CANCELLED"]; onActivated: { window.taskStatusFilter = currentText; window.taskPage = 0 } }
                                    BodyText { text: "Sort" }
                                    ComboBox { id: taskSortSelector; Layout.preferredWidth: 170; textRole: "label"; valueRole: "key"; model: [{"label":"Title","key":"title"},{"label":"Status","key":"status"},{"label":"Target branch","key":"target_branch"}]; onActivated: { window.taskSortKey = currentValue; window.taskPage = 0 } }
                                    QuietButton { text: window.taskSortAscending ? "Ascending" : "Descending"; onClicked: window.taskSortAscending = !window.taskSortAscending }
                                    Item { Layout.fillWidth: true }
                                    MutedText { text: taskFilteredRows().length + " task(s)" }
                                }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; model: taskPageRows(); clip: true
                                    delegate: Rectangle {
                                        width: ListView.view.width; height: 76; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout {
                                            anchors.fill: parent; anchors.margins: 12
                                            ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.title, modelData.id); font.weight: Font.DemiBold; elide: Text.ElideRight; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: window.text(modelData.objective, "No objective") + " • " + window.text(modelData.target_branch, "no branch"); elide: Text.ElideMiddle; maximumLineCount: 1 } }
                                            StatusPill { value: window.text(modelData.status, "INTAKE") }
                                            QuietButton { text: "Details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } }
                                            GoldButton { text: "Start"; enabled: String(modelData.status || "INTAKE").toUpperCase() === "INTAKE"; onClicked: keeper.startTask(modelData.id) }
                                        }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No tasks queued"; detail: "Keeper creates tasks from approved workflows, or you may add a bounded task to a registered repository." }
                                }
                                RowLayout { Layout.fillWidth: true; Item { Layout.fillWidth: true } QuietButton { text: "Previous"; enabled: taskSafePage() > 0; onClicked: window.taskPage = taskSafePage() - 1 } MutedText { text: "Page " + (taskSafePage() + 1) + " of " + taskPageCount() } QuietButton { text: "Next"; enabled: taskSafePage() + 1 < taskPageCount(); onClicked: window.taskPage = taskSafePage() + 1 } }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: findingColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: findingColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Findings"; subtitle: "Source-backed audit and verification findings. Severity is never decorative."; actionText: "Exportable Reports"; onAction: keeper.navigate("Reports") }
                            MutedText { text: "Repair is enabled only when a durable repair-required review is linked; otherwise inspection remains read-only."; color: warning }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 500
                                SectionTitle { text: "ENGINEERING FINDINGS" }
                                RowLayout { Layout.fillWidth: true
                                    BodyText { text: "Severity" }
                                    ComboBox { Layout.preferredWidth: 140; model: ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"]; onActivated: window.findingSeverityFilter = currentText }
                                    BodyText { text: "Status" }
                                    ComboBox { Layout.preferredWidth: 160; model: ["ALL", "OPEN", "REPAIR_REQUIRED", "REPAIRED", "VERIFIED"]; onActivated: window.findingStatusFilter = currentText }
                                    BodyText { text: "Repair" }
                                    ComboBox { Layout.preferredWidth: 140; model: ["ALL", "REPAIRED", "UNREPAIRED"]; onActivated: window.findingRepairFilter = currentText }
                                    Item { Layout.fillWidth: true }
                                }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; model: filteredFindings(); clip: true
                                    delegate: Rectangle {
                                        width: ListView.view.width; height: 82; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12
                                            ColumnLayout { Layout.fillWidth: true; BodyText { text: window.text(modelData.title, modelData.id); font.weight: Font.DemiBold } MutedText { text: window.text(modelData.description, "Recorded verification finding") } }
                                            StatusPill { value: window.text(modelData.severity, modelData.status) }
                                            QuietButton { text: "Details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } }
                                            GoldButton { text: "Create Repair"; visible: !!modelData.review_id; enabled: String(modelData.status || "").toUpperCase() === "REPAIR_REQUIRED"; onClicked: keeper.createRepair(modelData.review_id) }
                                        }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No recorded findings"; detail: "Independent review and verification findings will appear here with their durable status." }
                                }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: authorizationColumn.implicitHeight + 48; clip: true
                        ColumnLayout { id: authorizationColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16; PageHeader { title: "Authorizations"; subtitle: "Founder approvals, delegated grants, capability use, expiry, and revocation."; actionText: "+ New Authorization"; actionEnabled: false } MutedText { text: "New authority is created only through the supported Founder/charter flow."; color: warning } KPanel { Layout.fillWidth: true; Layout.preferredHeight: 510; SectionTitle { text: "DURABLE AUTHORITY RECORDS" } ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.authorizations || []); clip: true; delegate: Rectangle { width: ListView.view.width; height: 76; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"; RowLayout { anchors.fill: parent; anchors.margins: 14; ColumnLayout { Layout.fillWidth: true; BodyText { text: window.text(modelData.capability, modelData.id); font.weight: Font.DemiBold } MutedText { text: "Scope: " + window.text(modelData.scope, modelData.task_id) } } StatusPill { value: modelData.revoked_at ? "REVOKED" : (modelData.consumed_at ? "CONSUMED" : "ACTIVE") } QuietButton { text: "Revoke"; enabled: !modelData.revoked_at && !modelData.consumed_at; onClicked: keeper.revokeAuthorization(modelData.id) } } } EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No authorization records"; detail: "Founder approvals and bounded delegated grants will be projected here." } } } }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: evidenceColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: evidenceColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Evidence"; subtitle: "Validated bundles and typed read-only references. Protected paths stay hidden."; actionText: "Exportable Reports"; onAction: keeper.navigate("Reports") }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 300; SectionTitle { text: "EVIDENCE BUNDLES" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.evidence || []); clip: true
                                    delegate: Rectangle { width: ListView.view.width; height: 72; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.evidence_id, "Evidence bundle"); font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: "Producer " + window.text(modelData.producer, "unknown") + " • digest " + window.text(modelData.digest, "unavailable"); elide: Text.ElideMiddle; maximumLineCount: 1 } } StatusPill { value: window.text(modelData.state, "UNTRUSTED") } QuietButton { text: "Safe details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No validated evidence"; detail: "Provider output remains untrusted until Keeper validates and binds it to an attempt." }
                                }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 300; SectionTitle { text: "TYPED EVIDENCE REFERENCES" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.evidenceReferences || []); clip: true
                                    delegate: Rectangle { width: ListView.view.width; height: 76; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.reference_id, "Typed reference"); font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: window.text(modelData.classification, "UNKNOWN") + " • source " + window.text(modelData.source_producer, "unknown") + " • " + window.text(modelData.size_bytes, "0") + " bytes • digest " + window.text(modelData.digest, "unavailable"); elide: Text.ElideMiddle; maximumLineCount: 1 } } StatusPill { value: window.text(modelData.review_state, modelData.validation_state) } QuietButton { text: "Preview metadata"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No typed references"; detail: "Validated references for independent review appear here without exposing protected local paths." }
                                }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 260; SectionTitle { text: "SAFE RUN EVIDENCE PREVIEW" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.runs || []); clip: true
                                    delegate: Rectangle { width: ListView.view.width; height: 72; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.id, "Run"); font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: "Redacted allowlisted text logs and digests only"; elide: Text.ElideRight; maximumLineCount: 1 } } QuietButton { text: "Preview logs"; onClicked: { var preview = keeper.evidenceDetails(modelData.id, "logs"); if (Object.keys(preview).length > 0) { window.selectedRecord = preview; recordDialog.open() } } } }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No run evidence"; detail: "Supported redacted text previews appear only for runs with validated Keeper evidence roots." }
                                }
                            }                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: reviewColumn.implicitHeight + 48; clip: true
                        ColumnLayout { id: reviewColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16; PageHeader { title: "Reviews"; subtitle: "Independent reviewer execution, evidence, disposition, and bounded repair." } KPanel { Layout.fillWidth: true; Layout.preferredHeight: 520; SectionTitle { text: "INDEPENDENT REVIEWS" } ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.reviews || []); clip: true; delegate: RecordRow { title: text(modelData.review_id, "Review"); subtitle: "Producer assignment " + text(modelData.assignment_id, "unknown") + " • reviewer " + text(modelData.reviewer_assignment_id, "unassigned"); state: text(modelData.disposition, modelData.state) } EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No completed reviews"; detail: "Keeper requires a distinct completed reviewer attempt and validated evidence before acceptance." } } } }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: reportColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: reportColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Reports"; subtitle: "Completion summaries derived from finalized protected evidence." }
                            RowLayout {
                                Layout.fillWidth: true
                                BodyText { text: "Availability"; font.weight: Font.DemiBold }
                                ComboBox {
                                    objectName: "reportAvailabilityFilter"
                                    model: ["ALL", "EXPORTABLE", "PENDING"]
                                    currentIndex: Math.max(0, model.indexOf(window.reportAvailabilityFilter))
                                    onActivated: window.reportAvailabilityFilter = currentText
                                }
                                Item { Layout.fillWidth: true }
                                MutedText { text: reportRows().length + " report(s)" }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 520; SectionTitle { text: "RUN REPORTS" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: reportRows(); clip: true
                                    delegate: Rectangle { width: ListView.view.width; height: 78; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; ColumnLayout { Layout.fillWidth: true; Layout.minimumWidth: 0; BodyText { Layout.fillWidth: true; text: window.text(modelData.id, "Run"); font.weight: Font.DemiBold; elide: Text.ElideMiddle; maximumLineCount: 1 } MutedText { Layout.fillWidth: true; text: "Task " + window.text(modelData.task_id, "unknown") + (modelData.evidence_manifest_digest ? " • finalized evidence available" : " • report unavailable until finalization"); elide: Text.ElideMiddle; maximumLineCount: 1 } } StatusPill { value: window.text(modelData.status, "UNKNOWN") } QuietButton { text: "Details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } GoldButton { text: "Export"; enabled: !!modelData.evidence_manifest_digest; onClicked: { window.selectedRunId = modelData.id; reportFileDialog.open() } } }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No run reports"; detail: "A report becomes available only after Keeper validates and finalizes the run evidence." }
                                }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: providerColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: providerColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Providers"; subtitle: "Qualified providers, accounts, sessions, declared capabilities, and usage."; actionText: "+ Register Provider"; actionEnabled: false }
                            MutedText { text: "Provider registration and qualification remain explicit KeeperAuthority operations; this desktop does not fabricate production authority."; color: warning }
                            RowLayout {
                                Layout.fillWidth: true
                                BodyText { text: "Session health"; font.weight: Font.DemiBold }
                                ComboBox {
                                    objectName: "providerHealthFilter"
                                    model: ["ALL", "READY", "NOT READY"]
                                    currentIndex: Math.max(0, model.indexOf(window.providerHealthFilter))
                                    onActivated: window.providerHealthFilter = currentText
                                }
                                Item { Layout.fillWidth: true }
                                MutedText { text: providerRows().length + " session(s)" }
                            }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 150
                                SectionTitle { text: "KEEPER PROVIDER HOST" }
                                RowLayout { Layout.fillWidth: true; StatusPill { value: keeper.state.providerHost ? window.text(keeper.state.providerHost.state, "NOT CONFIGURED") : "NOT CONFIGURED" } BodyText { Layout.fillWidth: true; text: keeper.state.providerHost ? "Protocol " + window.text(keeper.state.providerHost.protocol, "not reported") + " • provider " + window.text(keeper.state.providerHost.provider_state, "UNAVAILABLE") + " • execution " + window.text(keeper.state.providerHost.execution_state, "IDLE") + " • usage " + window.text(keeper.state.providerHost.usage_state, "UNAVAILABLE") : "Per-user execution deputy not configured" } }
                                MutedText { text: keeper.state.providerHost && keeper.state.providerHost.founder_action_required ? "Founder action required: " + keeper.state.providerHost.founder_action_required : "No Founder action required."; color: keeper.state.providerHost && keeper.state.providerHost.founder_action_required ? warning : success }
                            }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 390
                                SectionTitle { text: "PROVIDER SESSIONS" }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; model: providerRows(); clip: true
                                    delegate: RecordRow {
                                        height: 82
                                        title: text(modelData.name, modelData.provider_id)
                                        subtitle: text(modelData.composition, "NOT CONFIGURED") + " • " + text(modelData.authentication_mode, "auth undeclared") + " • " + text(modelData.billing_mode, "billing undeclared") + "\nmodels " + (modelData.model_allowlist || []).join(", ") + " • efforts " + (modelData.effort_levels || []).join(", ") + " • usage " + text(modelData.usage_state, "UNKNOWN") + " • reviewer " + text(modelData.reviewer_status, "UNKNOWN") + " • API billing " + text(modelData.api_billing, "DISABLED") + " • paid fallback " + text(modelData.paid_fallback, "DISABLED")
                                        state: text(modelData.health, "UNAVAILABLE")
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No qualified provider sessions"; detail: "Configure an executable path in Settings, then use the approved Authority workflow to register and qualify it." }
                                }
                            }
                            KPanel {
                                Layout.fillWidth: true; Layout.preferredHeight: 260
                                SectionTitle { text: "USAGE POOLS" }
                                ListView {
                                    Layout.fillWidth: true; Layout.fillHeight: true; model: filtered(keeper.state.usage || []); clip: true
                                    delegate: RecordRow { title: text(modelData.pool_id, "Usage pool"); subtitle: "Consumed " + text(modelData.consumed, "0") + " • reserved " + text(modelData.reserved, "0") + " • remaining " + text(modelData.remaining, "unknown") + " • source " + text(modelData.source, "UNKNOWN") + " • confidence " + text(modelData.confidence, "UNKNOWN"); state: text(modelData.status, "AVAILABLE") }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No usage pools"; detail: "Durable shared-pool accounting appears after a qualified provider session is configured." }
                                }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: recoveryColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: recoveryColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Recovery"; subtitle: "Conservative crash, cancellation, uncertainty, and restore projections." }
                            RowLayout {
                                Layout.fillWidth: true
                                BodyText { text: "Action state"; font.weight: Font.DemiBold }
                                ComboBox {
                                    objectName: "recoveryStatusFilter"
                                    model: ["ALL", "UNCERTAIN", "RESUMABLE"]
                                    currentIndex: Math.max(0, model.indexOf(window.recoveryStatusFilter))
                                    onActivated: window.recoveryStatusFilter = currentText
                                }
                                Item { Layout.fillWidth: true }
                                MutedText { text: recoveryRows().length + " record(s)" }
                            }
                            RowLayout { Layout.fillWidth: true; spacing: 14
                                KPanel { Layout.fillWidth: true; Layout.preferredHeight: 170; SectionTitle { text: "UNCERTAIN" } Text { text: keeper.state.counts ? keeper.state.counts.uncertain : 0; color: warning; font.pixelSize: 36 } MutedText { text: "Non-idempotent uncertain work is never retried automatically." } }
                                KPanel { Layout.fillWidth: true; Layout.preferredHeight: 170; SectionTitle { text: "KEEPERAUTHORITY" } StatusPill { value: keeper.state.diagnostics ? window.text(keeper.state.diagnostics.authorityStatus, "UNAVAILABLE") : "UNAVAILABLE" } MutedText { text: "Health is read-only and grants no execution authority." } }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 380; SectionTitle { text: "RECOVERY RECORDS" }
                                ListView { Layout.fillWidth: true; Layout.fillHeight: true; model: recoveryRows(); clip: true
                                    delegate: Rectangle { width: ListView.view.width; height: 78; color: index % 2 ? "#141616" : "#101212"; border.color: "#292B2A"
                                        RowLayout { anchors.fill: parent; anchors.margins: 12; ColumnLayout { Layout.fillWidth: true; BodyText { text: window.text(modelData.id, modelData.run_id); font.weight: Font.DemiBold } MutedText { text: window.text(modelData.reason, "Recovery state requires inspection") } } StatusPill { value: window.text(modelData.status, "UNKNOWN") } QuietButton { text: "Details"; onClicked: { window.selectedRecord = modelData; recordDialog.open() } } GoldButton { visible: String(modelData.source || "") === "pass_b_uncertain_execution"; text: "Resolve safely"; onClicked: keeper.resolveUncertainExecution(modelData.assignment_id) } GoldButton { visible: String(modelData.source || "") !== "pass_b_uncertain_execution"; text: modelData.recovery_action === "retry" ? "Retry stage" : "Resume"; enabled: !!modelData.run_id && (modelData.recovery_action === "resume" || modelData.recovery_action === "retry") && String(modelData.status || "").toUpperCase() !== "UNCERTAIN"; onClicked: keeper.runAction(modelData.run_id, modelData.recovery_action) } }
                                    }
                                    EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "No recovery action required"; detail: "Keeper currently has no source-backed interrupted or uncertain run requiring attention." }
                                }
                            }
                        }
                    }

                    Flickable {
                        contentWidth: width; contentHeight: settingsColumn.implicitHeight + 48; clip: true
                        ColumnLayout {
                            id: settingsColumn; width: parent.width - 48; x: 24; y: 24; spacing: 16
                            PageHeader { title: "Settings"; subtitle: "Local paths, presentation, environment labeling, and read-only service health." }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 240; SectionTitle { text: "SAFETY & PRESENTATION" }
                                RowLayout { Layout.fillWidth: true; ColumnLayout { Layout.fillWidth: true; BodyText { text: "Local-only mode" } MutedText { text: "No provider is selected automatically and paid fallback is disabled." } } Switch { checked: true; enabled: false } }
                                RowLayout { Layout.fillWidth: true; ColumnLayout { Layout.fillWidth: true; BodyText { text: "Show developer details" } MutedText { text: "Expose durable IDs and diagnostics; protected paths remain redacted." } } Switch { checked: keeper.state.settings ? keeper.state.settings.developerDetails : false; onToggled: keeper.setDeveloperDetails(checked) } }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 390; SectionTitle { text: "PATHS" }
                                BodyText { text: "Evidence directory" }
                                RowLayout { Layout.fillWidth: true; MutedText { Layout.fillWidth: true; text: keeper.state.settings ? keeper.state.settings.evidenceDirectory : "Not configured" } QuietButton { text: "Change…"; onClicked: { folderDialog.mode = "settingsEvidence"; folderDialog.open() } } }
                                BodyText { text: "Configured provider executable identities" }
                                Repeater { model: keeper.state.settings ? Object.keys(keeper.state.settings.providerPaths || {}) : []; RowLayout { Layout.fillWidth: true; MutedText { Layout.preferredWidth: 120; text: modelData } MutedText { Layout.fillWidth: true; text: keeper.state.settings.providerPaths[modelData] } } }
                                MutedText { Layout.fillWidth: true; visible: !(keeper.state.settings && Object.keys(keeper.state.settings.providerPaths || {}).length); text: "No provider executable path is configured. Saving a path never registers or qualifies a provider."; color: warning }
                                RowLayout { Layout.fillWidth: true; TextField { id: settingsProviderName; objectName: "settingsProviderName"; Layout.preferredWidth: 140; Layout.minimumWidth: 110; placeholderText: "Provider name"; color: textPrimary; background: Rectangle { color: "#101212"; border.color: parent.activeFocus ? gold : "#393B3A"; radius: 4 } } TextField { id: settingsProviderPath; objectName: "settingsProviderPath"; Layout.fillWidth: true; Layout.minimumWidth: 150; placeholderText: "Existing executable path"; color: textPrimary; background: Rectangle { color: "#101212"; border.color: parent.activeFocus ? gold : "#393B3A"; radius: 4 } } QuietButton { text: "Browse…"; onClicked: providerFileDialog.open() } GoldButton { text: "Validate & Save"; enabled: settingsProviderName.text.trim().length > 0 && settingsProviderPath.text.trim().length > 0; onClicked: keeper.setProviderPath(settingsProviderName.text, settingsProviderPath.text) } }
                                RowLayout { Layout.alignment: Qt.AlignRight; QuietButton { objectName: "settingsCancel"; text: "Cancel"; onClicked: { settingsProviderName.clear(); settingsProviderPath.clear(); keeper.refresh() } } QuietButton { text: "Reset presentation"; onClicked: keeper.resetPresentationSettings() } }
                            }
                            KPanel { Layout.fillWidth: true; Layout.preferredHeight: 360; SectionTitle { text: "KEEPERAUTHORITY HEALTH" } StatusPill { value: keeper.state.diagnostics ? window.text(keeper.state.diagnostics.authorityStatus, "UNAVAILABLE") : "UNAVAILABLE" } ScrollView { Layout.fillWidth: true; Layout.fillHeight: true; clip: true; Text { width: parent.width; color: textMuted; font.pixelSize: 12; wrapMode: Text.WrapAnywhere; textFormat: Text.PlainText; text: keeper.state.diagnostics && keeper.state.diagnostics.authority ? JSON.stringify(keeper.state.diagnostics.authority, null, 2) : "No supported health response is available." } } MutedText { Layout.fillWidth: true; text: "This health projection is read-only and cannot launch, install, restart, or reconfigure the service."; color: warning } }
                        }
                    }
                }

                Rectangle {
                    id: assistantDrawer
                    objectName: "assistantDrawer"
                    property bool userOpened: false
                    readonly property bool opened: userOpened && window.width >= 1360
                    Layout.preferredWidth: opened ? 330 : 44
                    Layout.fillHeight: true
                    color: "#0D0F0E"
                    border.color: border
                    Behavior on Layout.preferredWidth { NumberAnimation { duration: 160 } }
                    ColumnLayout {
                        anchors.fill: parent; anchors.margins: 14; spacing: 10
                        RowLayout {
                            Layout.fillWidth: true
                            Image { visible: assistantDrawer.opened; source: keeperIcon; sourceSize.width: 42; sourceSize.height: 42; Layout.preferredWidth: 42; Layout.preferredHeight: 42 }
                            BodyText { visible: assistantDrawer.opened; Layout.fillWidth: true; text: "Keeper Assistant"; font.pixelSize: 17; font.weight: Font.DemiBold }
                            QuietButton { objectName: "assistantToggle"; text: assistantDrawer.opened ? "×" : "◀"; implicitWidth: 36; onClicked: { if (window.width < 1360) narrowAssistantDialog.open(); else assistantDrawer.userOpened = !assistantDrawer.userOpened } }
                        }
                        MutedText { visible: assistantDrawer.opened; Layout.fillWidth: true; text: "Describe what you want. Keeper develops the idea with you, prepares the charter, and carries out the approved project."; wrapMode: Text.WordWrap }
                        Rectangle { visible: assistantDrawer.opened; Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                        ListView {
                            visible: assistantDrawer.opened
                            Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 8
                            model: keeper.state.timeline || []
                            delegate: Rectangle {
                                width: ListView.view.width; implicitHeight: message.implicitHeight + 28; radius: 7
                                color: modelData.kind === "founder" ? "#242525" : "#171A18"; border.color: modelData.kind === "founder" ? "#4B4B48" : goldDim
                                Text { id: message; anchors.fill: parent; anchors.margins: 14; text: modelData.body; color: textPrimary; font.pixelSize: 12; wrapMode: Text.Wrap; textFormat: Text.PlainText }
                            }
                            EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "What do you want to make?"; detail: "Talk naturally. Keeper will ask questions, prepare the project, and guide you through the one required approval." }
                        }
                        RowLayout {
                            visible: assistantDrawer.opened
                            Layout.fillWidth: true
                            TextArea {
                                id: assistantInput
                                objectName: "assistantInput"
                                Layout.fillWidth: true; Layout.preferredHeight: 72
                                placeholderText: "Tell Keeper what you want to build…"
                                color: textPrimary; placeholderTextColor: "#777777"; wrapMode: TextEdit.Wrap
                                background: Rectangle { color: "#141616"; border.color: parent.activeFocus ? gold : "#3A3C3A"; radius: 5 }
                            }
                            GoldButton { objectName: "assistantSend"; text: keeper.busy ? "Working…" : "Send"; enabled: assistantInput.text.trim().length > 0 && !keeper.busy; onClicked: { keeper.sendAssistantMessage(assistantInput.text); assistantInput.clear() } }
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true; Layout.preferredHeight: 34
                color: "#0A0C0B"; border.color: "#242625"
                RowLayout { anchors.fill: parent; anchors.leftMargin: 18; anchors.rightMargin: 18; Rectangle { Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4; color: keeper.error ? danger : success } MutedText { Layout.fillWidth: true; text: keeper.error ? keeper.error : keeper.status; color: keeper.error ? danger : textMuted } MutedText { text: "Authority effect: governed by Keeper services" } }
            }
        }
    }

    Dialog {
        id: narrowAssistantDialog
        objectName: "narrowAssistantDialog"
        anchors.centerIn: parent
        width: Math.min(520, window.width - 48)
        height: Math.min(680, window.height - 48)
        modal: true
        title: "Keeper Assistant"
        standardButtons: Dialog.Close
        background: Rectangle { color: panelRaised; border.color: goldDim; radius: 8 }
        contentItem: ColumnLayout {
            spacing: 10
            MutedText { Layout.fillWidth: true; text: "Describe what you want. Keeper develops the idea with you, prepares the charter, and carries out the approved project."; wrapMode: Text.Wrap }
            ListView {
                Layout.fillWidth: true; Layout.fillHeight: true; clip: true; spacing: 8
                model: keeper.state.timeline || []
                delegate: Rectangle {
                    width: ListView.view.width; implicitHeight: narrowMessage.implicitHeight + 28; radius: 7
                    color: modelData.kind === "founder" ? "#242525" : "#171A18"; border.color: modelData.kind === "founder" ? "#4B4B48" : goldDim
                    Text { id: narrowMessage; anchors.fill: parent; anchors.margins: 14; text: modelData.body; color: textPrimary; font.pixelSize: 12; wrapMode: Text.Wrap; textFormat: Text.PlainText }
                }
                EmptyState { anchors.fill: parent; visible: parent.count === 0; title: "What do you want to make?"; detail: "Talk naturally. Keeper will ask questions, prepare the project, and guide you through the one required approval." }
            }
            TextArea {
                id: narrowAssistantInput
                objectName: "narrowAssistantInput"
                Layout.fillWidth: true; Layout.preferredHeight: 90
                placeholderText: "Tell Keeper what you want to build…"
                color: textPrimary; placeholderTextColor: "#777777"; wrapMode: TextEdit.Wrap
                background: Rectangle { color: "#141616"; border.color: parent.activeFocus ? gold : "#3A3C3A"; radius: 5 }
            }
            GoldButton { objectName: "narrowAssistantSend"; Layout.alignment: Qt.AlignRight; text: keeper.busy ? "Working…" : "Send"; enabled: narrowAssistantInput.text.trim().length > 0 && !keeper.busy; onClicked: { keeper.sendAssistantMessage(narrowAssistantInput.text); narrowAssistantInput.clear() } }
        }
    }

    Dialog {
        id: charterDialog
        objectName: "founderApprovalDialog"
        anchors.centerIn: parent
        width: Math.min(650, window.width - 80)
        modal: true
        title: "Founder Approval Required"
        standardButtons: Dialog.NoButton
        background: Rectangle { color: panelRaised; border.color: gold; radius: 8 }
        contentItem: ColumnLayout {
            spacing: 14
            Image { Layout.alignment: Qt.AlignHCenter; source: keeperIcon; sourceSize.width: 100; sourceSize.height: 100; Layout.preferredWidth: 100; Layout.preferredHeight: 100 }
            Text { Layout.alignment: Qt.AlignHCenter; text: "Approve Project Charter"; color: goldBright; font.pixelSize: 23; font.weight: Font.Bold }
            BodyText { Layout.fillWidth: true; text: window.text(keeper.state.project ? keeper.state.project.title : "", "Current project"); horizontalAlignment: Text.AlignHCenter }
            MutedText { Layout.fillWidth: true; text: "Revision " + window.text(keeper.state.project && keeper.state.project.approvalCharter ? keeper.state.project.approvalCharter.revision : "", "unknown") + "  •  Mode: " + window.currentDelegationMode(); horizontalAlignment: Text.AlignHCenter }
            MutedText { Layout.fillWidth: true; text: "Approved providers: " + window.text(keeper.state.project && keeper.state.project.approvalCharter ? keeper.state.project.approvalCharter.approved_providers : "", "none"); horizontalAlignment: Text.AlignHCenter; wrapMode: Text.Wrap }
            MutedText { Layout.fillWidth: true; text: "Constraints: " + window.text(keeper.state.project && keeper.state.project.approvalCharter ? keeper.state.project.approvalCharter.constraints : "", "none"); horizontalAlignment: Text.AlignHCenter; wrapMode: Text.Wrap }
            MutedText { Layout.fillWidth: true; text: "After authentication, Keeper chooses the safest effective plan and keeps the project moving inside this charter without asking you to manage tasks or workflows."; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.Wrap }
            RowLayout { Layout.alignment: Qt.AlignHCenter; QuietButton { text: "Cancel"; onClicked: charterDialog.close() } GoldButton { objectName: "confirmFounderApproval"; text: "Authenticate & Approve"; onClicked: { charterDialog.close(); keeper.approveCurrentCharter() } } }
        }
    }

    Dialog {
        id: delegatedModeDialog
        objectName: "delegatedModeDialog"
        anchors.centerIn: parent
        width: Math.min(620, window.width - 80)
        modal: true
        title: "Enable Approved Work"
        standardButtons: Dialog.NoButton
        background: Rectangle { color: panelRaised; border.color: gold; radius: 8 }
        contentItem: ColumnLayout {
            spacing: 14
            Text { Layout.alignment: Qt.AlignHCenter; text: "One approval enables this workflow"; color: goldBright; font.pixelSize: 22; font.weight: Font.Bold }
            BodyText { Layout.fillWidth: true; text: "Keeper is currently in Advisory mode, so it can plan but cannot run Codex or another provider."; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.Wrap }
            MutedText { Layout.fillWidth: true; text: "Prepare a Delegated-mode revision. Your existing workspace, provider, spending, deployment, publishing, and push limits stay unchanged. Nothing runs until you review and authenticate the revision."; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.Wrap }
            RowLayout {
                Layout.alignment: Qt.AlignHCenter
                QuietButton { text: "Cancel"; onClicked: delegatedModeDialog.close() }
                GoldButton { objectName: "prepareDelegatedMode"; text: "Prepare Revision"; onClicked: { delegatedModeDialog.close(); keeper.prepareDelegatedMode() } }
            }
        }
    }

    Dialog {
        id: addRepositoryDialog; anchors.centerIn: parent; width: 620; modal: true; title: "Add Protected Repository"; standardButtons: Dialog.NoButton
        background: Rectangle { color: panelRaised; border.color: goldDim; radius: 7 }
        contentItem: ColumnLayout { spacing: 12; BodyText { text: "Repository name" } TextField { id: repoName; Layout.fillWidth: true; color: textPrimary; background: Rectangle { color: "#111111"; border.color: "#444444" } } BodyText { text: "Local Git repository" } RowLayout { Layout.fillWidth: true; TextField { id: repoPath; Layout.fillWidth: true; color: textPrimary; background: Rectangle { color: "#111111"; border.color: "#444444" } } QuietButton { objectName: "browseRepository"; text: "Browse"; onClicked: { folderDialog.mode = "addRepository"; folderDialog.open() } } } MutedText { text: "Keeper protects the original and uses isolated workspaces for execution." } RowLayout { Layout.alignment: Qt.AlignRight; QuietButton { text: "Cancel"; onClicked: addRepositoryDialog.close() } GoldButton { objectName: "confirmAddRepository"; text: "Add Repository"; enabled: repoPath.text.length > 0; onClicked: { keeper.addRepository(repoPath.text, repoName.text); addRepositoryDialog.close() } } } }
    }

    Dialog {
        id: taskDialog; anchors.centerIn: parent; width: 650; modal: true; title: "Create a Task"; standardButtons: Dialog.NoButton
        background: Rectangle { color: panelRaised; border.color: goldDim; radius: 7 }
        contentItem: ColumnLayout { spacing: 9; MutedText { Layout.fillWidth: true; text: "Tell Keeper what you want done. Keeper will use the current repository and create a safe local branch for you."; wrapMode: Text.WordWrap } BodyText { text: "Task name" } TextField { id: taskTitle; Layout.fillWidth: true; placeholderText: "Example: Clean up the workflow screen"; color: textPrimary; background: Rectangle { color: "#111111"; border.color: "#444444" } } BodyText { text: "What should Keeper do?" } TextArea { id: taskObjective; Layout.fillWidth: true; Layout.preferredHeight: 110; placeholderText: "Describe the result you want and anything Keeper must not change."; color: textPrimary; wrapMode: TextEdit.Wrap; background: Rectangle { color: "#111111"; border.color: "#444444" } } MutedText { Layout.fillWidth: true; text: "Nothing will be committed, pushed, deployed, published, or purchased without your approval."; color: warning; wrapMode: Text.WordWrap } RowLayout { Layout.alignment: Qt.AlignRight; QuietButton { text: "Cancel"; onClicked: taskDialog.close() } GoldButton { objectName: "confirmCreateTask"; text: "Add Task"; enabled: taskTitle.text.trim().length > 0 && taskObjective.text.trim().length > 0; onClicked: { keeper.createSimpleTask(taskTitle.text, taskObjective.text); taskDialog.close() } } } }
    }

    Dialog {
        id: recordDialog
        anchors.centerIn: parent
        width: Math.min(760, window.width - 80)
        modal: true
        title: "Keeper details"
        standardButtons: Dialog.Close
        background: Rectangle { color: panelRaised; border.color: goldDim; radius: 7 }
        contentItem: ScrollView { implicitHeight: 440; TextArea { readOnly: true; text: (keeper.state.settings && keeper.state.settings.developerDetails) ? JSON.stringify(window.selectedRecord || {}, null, 2) : window.friendlyRecord(window.selectedRecord); color: textPrimary; wrapMode: TextEdit.WrapAnywhere; background: Rectangle { color: "#101212"; border.color: "#333534" } } }
    }

    FileDialog {
        id: providerFileDialog
        title: "Choose Provider Executable"
        fileMode: FileDialog.OpenFile
        onAccepted: settingsProviderPath.text = selectedFile
    }

    FileDialog {
        id: reportFileDialog
        title: "Export Validated Keeper Report"
        fileMode: FileDialog.SaveFile
        nameFilters: ["JSON report (*.json)"]
        onAccepted: keeper.exportRunReport(window.selectedRunId, selectedFile)
    }

    FolderDialog {
        id: folderDialog
        property string mode: "addRepository"
        title: (mode === "evidence" || mode === "settingsEvidence") ? "Choose Evidence Directory" : "Choose Git Repository"
        onAccepted: {
            if (mode === "addRepository") repoPath.text = selectedFolder
            else if (mode === "setupRepository") {
                setupRepository.text = selectedFolder
                keeper.setSetupValue("repository", selectedFolder)
            } else if (mode === "settingsEvidence") keeper.setEvidenceDirectory(selectedFolder)
            else keeper.setSetupValue("evidenceDirectory", selectedFolder)
        }
    }

    Rectangle {
        id: setupOverlay
        visible: keeper.setupRequired
        anchors.fill: parent
        z: 100
        color: "#080909"
        RowLayout {
            anchors.fill: parent; anchors.margins: 26; spacing: 24
            KPanel {
                Layout.preferredWidth: 300; Layout.fillHeight: true
                Image { Layout.alignment: Qt.AlignHCenter; source: keeperIcon; sourceSize.width: 170; sourceSize.height: 170; Layout.preferredWidth: 180; Layout.preferredHeight: 180 }
                Text { Layout.alignment: Qt.AlignHCenter; text: "K E E P E R"; color: goldBright; font.pixelSize: 24; font.family: "Georgia" }
                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                Repeater {
                    model: ["Safety Boundaries", "Evidence Storage", "Repository / Project", "Provider Configuration", "Provider Validation", "KeeperAuthority Health", "Finish"]
                    RowLayout {
                        Layout.fillWidth: true
                        Rectangle { Layout.preferredWidth: 30; Layout.preferredHeight: 30; radius: 15; color: index === keeper.setupIndex ? gold : (index < keeper.setupIndex ? "#315F36" : "#242625"); Text { anchors.centerIn: parent; text: index + 1; color: index === keeper.setupIndex ? "#080808" : textPrimary; font.weight: Font.Bold } }
                        ColumnLayout { Layout.fillWidth: true; BodyText { text: modelData; color: index === keeper.setupIndex ? goldBright : textMuted; font.weight: index === keeper.setupIndex ? Font.DemiBold : Font.Normal } MutedText { visible: index === keeper.setupIndex; text: index === 0 ? "Define local safety boundaries" : index === 1 ? "Choose protected evidence storage" : index === 2 ? "Select an optional first repository" : index === 3 ? "Choose provider routing policy" : index === 4 ? "Review qualification requirements" : index === 5 ? "Verify read-only service status" : "Commit setup and open Keeper" } }
                    }
                }
                Item { Layout.fillHeight: true }
                MutedText { text: "Local. Private. Under your control."; Layout.alignment: Qt.AlignHCenter; color: gold }
            }
            KPanel {
                Layout.fillWidth: true; Layout.fillHeight: true
                RowLayout { Layout.fillWidth: true; ColumnLayout { Layout.fillWidth: true; Text { text: "Welcome to Keeper"; color: goldBright; font.pixelSize: 32; font.weight: Font.DemiBold } MutedText { text: "Set up your local executive workflow in seven clear steps."; font.pixelSize: 15 } } Image { source: keeperIcon; sourceSize.width: 110; sourceSize.height: 110; Layout.preferredWidth: 110; Layout.preferredHeight: 110 } }
                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                StackLayout {
                    Layout.fillWidth: true; Layout.fillHeight: true; currentIndex: keeper.setupIndex
                    ColumnLayout { SectionTitle { text: "STEP 1 OF 7 — SAFETY BOUNDARIES" } BodyText { text: "Keeper executes only inside an approved charter and durable authority envelope."; font.pixelSize: 20 } Repeater { model: ["Original repositories stay protected", "No paid fallback or spending", "No deployment, publication, or live trading", "Founder approval is required for authority expansion"]; RowLayout { Rectangle { Layout.preferredWidth: 9; Layout.preferredHeight: 9; radius: 5; color: success } BodyText { text: modelData } } } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 2 OF 7 — EVIDENCE STORAGE" } BodyText { text: "Choose where Keeper stores durable evidence and local state."; font.pixelSize: 20 } TextField { Layout.fillWidth: true; text: keeper.setupDraft.evidenceDirectory; readOnly: true; color: textPrimary; background: Rectangle { color: "#101212"; border.color: "#444444" } } QuietButton { objectName: "setupBrowseEvidence"; text: "Browse…"; onClicked: { folderDialog.mode = "evidence"; folderDialog.open() } } MutedText { text: "Keeper validates protected-tree boundaries and uses an exclusive random write probe before accepting this directory." } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 3 OF 7 — FIRST PROJECT" } BodyText { text: "Optionally select a local Git repository. You can also start from a conversation later."; font.pixelSize: 20 } TextField { id: setupRepository; Layout.fillWidth: true; text: keeper.setupDraft.repository; color: textPrimary; placeholderText: "Optional local Git repository"; background: Rectangle { color: "#101212"; border.color: "#444444" } onTextChanged: keeper.setSetupValue("repository", text) } QuietButton { text: "Browse…"; onClicked: { folderDialog.mode = "setupRepository"; folderDialog.open() } } MutedText { text: "The original repository is recorded as protected. Provider work uses isolated workspaces." } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 4 OF 7 — PROVIDER CONFIGURATION" } BodyText { text: "Choose a routing policy. Keeper never preselects a paid cloud provider."; font.pixelSize: 20 } ComboBox { id: setupPolicy; model: ["automatic", "local-only", "strongest"].concat(Object.keys(keeper.state.settings ? keeper.state.settings.providerPaths || {} : {})); currentIndex: Math.max(0, model.indexOf(keeper.setupDraft.providerPolicy)); onActivated: keeper.setSetupValue("providerPolicy", currentText) } MutedText { text: "Executable paths may be configured later in Settings. Registration and qualification remain separate supported Authority operations." } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 5 OF 7 — PROVIDER VALIDATION" } BodyText { text: "No provider is treated as production-ready until KeeperAuthority validates its identity and declared capabilities."; font.pixelSize: 20 } StatusPill { value: (keeper.state.providers || []).length > 0 ? "AVAILABLE" : "NOT CONFIGURED" } MutedText { text: "It is safe to finish setup without a provider. Conversation, charter drafting, diagnostics, and local project organization remain available." } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 6 OF 7 — KEEPERAUTHORITY HEALTH" } BodyText { text: "Keeper performs a read-only identity and protocol health check."; font.pixelSize: 20 } StatusPill { value: keeper.state.diagnostics ? text(keeper.state.diagnostics.authorityStatus, "UNAVAILABLE") : "UNAVAILABLE" } MutedText { text: "Unavailable service status does not crash setup and grants no execution authority. This wizard never starts, installs, restarts, or reconfigures the service." } Item { Layout.fillHeight: true } }
                    ColumnLayout { SectionTitle { text: "STEP 7 OF 7 — READY" } BodyText { text: "Review the safety contract and open Keeper."; font.pixelSize: 20 } Repeater { model: ["Evidence directory validated", "Original repositories remain protected", "Provider state is honestly labeled", "KeeperAuthority health is read-only", "No network, paid-provider, deployment, or trading action occurred"]; RowLayout { Rectangle { Layout.preferredWidth: 9; Layout.preferredHeight: 9; radius: 5; color: success } BodyText { text: modelData } } } Item { Layout.fillHeight: true } }
                }
                MutedText { visible: keeper.error.length > 0; Layout.fillWidth: true; text: keeper.error; color: danger; wrapMode: Text.Wrap }
                Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: border }
                RowLayout { Layout.fillWidth: true; QuietButton { text: "Cancel setup"; onClicked: Qt.quit() } QuietButton { objectName: "setupBack"; text: "Back"; enabled: keeper.setupIndex > 0; onClicked: keeper.setupBack() } QuietButton { objectName: "setupRetry"; visible: keeper.error.length > 0; text: "Retry validation"; onClicked: keeper.setupNext() } Item { Layout.fillWidth: true } GoldButton { objectName: "setupNext"; visible: keeper.setupIndex < 6; text: "Next ›"; onClicked: keeper.setupNext() } GoldButton { objectName: "setupFinish"; visible: keeper.setupIndex === 6; text: "Finish & Open Keeper"; onClicked: keeper.finishSetup() } }
            }
        }
    }
}
