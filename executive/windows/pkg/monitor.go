// +build windows

package pkg

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"time"

	"golang.org/x/sys/windows/svc"

	"github.com/lxn/walk"
	"github.com/lxn/walk/declarative"
)

const about = `
Shadow: A Transparent Proxy for Windows, Linux and macOS
Developed by John Xiong (https://imgk.cc)
https://github.com/imgk/shadow
`

type ManagerWindow struct {
	*walk.MainWindow
	ServiceName string
	ServiceDesc string

	icon           *walk.Icon
	boxServer      *walk.ComboBox
	boxMode        *walk.ComboBox
	buttonInstall  *walk.PushButton
	buttonRemove   *walk.PushButton
	buttonGenerate *walk.PushButton
	buttonStart    *walk.PushButton
	buttonStop     *walk.PushButton
	itemStatus     *walk.StatusBarItem
	menus          []declarative.MenuItem
	statusBar      []declarative.StatusBarItem
	serverSlice    []string
	ruleSlice      []string
	ruleMap        map[string]string
}

func (m *ManagerWindow) setup() (err error) {
	m.menus = []declarative.MenuItem{
		declarative.Menu{
			Text: "&Server",
			Items: []declarative.MenuItem{
				declarative.Action{
					Text:        "&Add",
					Enabled:     declarative.Bind("enabledCB.Checked"),
					Visible:     declarative.Bind("!openHiddenCB.Checked"),
					Shortcut:    declarative.Shortcut{walk.ModControl, walk.KeyA},
					OnTriggered: m.Add,
				},
				declarative.Action{
					Text:        "E&xit",
					OnTriggered: m.Hide,
				},
			},
		},
		declarative.Menu{
			Text: "&Help",
			Items: []declarative.MenuItem{
				declarative.Action{
					Text:        "About",
					OnTriggered: m.About,
				},
			},
		},
	}

	m.statusBar = []declarative.StatusBarItem{
		declarative.StatusBarItem{
			AssignTo: &m.itemStatus,
			Text:     "",
		},
	}

	err = declarative.MainWindow{
		AssignTo:       &m.MainWindow,
		Name:           "Shadow",
		Title:          "Shadow: A Transparent Proxy for Windows, Linux and macOS",
		Icon:           m.icon,
		Persistent:     true,
		Layout:         declarative.VBox{},
		MenuItems:      m.menus,
		StatusBarItems: m.statusBar,
		Children: []declarative.Widget{
			declarative.GroupBox{
				Title:  "Shadow Config",
				Layout: declarative.VBox{},
				Children: []declarative.Widget{
					declarative.Composite{
						Layout: declarative.Grid{Columns: 2},
						Children: []declarative.Widget{
							declarative.TextLabel{
								Text: "Server",
							},
							declarative.ComboBox{
								AssignTo: &m.boxServer,
								Editable: true,
							},
							declarative.TextLabel{
								Text: "Mode",
							},
							declarative.ComboBox{
								AssignTo: &m.boxMode,
								Editable: true,
							},
						},
					},
				},
			},
			declarative.Composite{
				Layout: declarative.Grid{Columns: 5},
				Children: []declarative.Widget{
					declarative.PushButton{
						AssignTo:  &m.buttonStart,
						Text:      "Install",
						OnClicked: m.Install,
					},
					declarative.PushButton{
						AssignTo:  &m.buttonStop,
						Text:      "Remove",
						OnClicked: m.Remove,
					},
					declarative.PushButton{
						AssignTo:  &m.buttonGenerate,
						Text:      "Generate",
						OnClicked: m.Generate,
					},
					declarative.PushButton{
						AssignTo:  &m.buttonStart,
						Text:      "Start",
						OnClicked: m.Start,
					},
					declarative.PushButton{
						AssignTo:  &m.buttonStop,
						Text:      "Stop",
						OnClicked: m.Stop,
					},
				},
			},
		},
	}.Create()
	if err != nil {
		return
	}

	m.MainWindow.SetSize(walk.Size{400, 175})
	m.MainWindow.Closing().Attach(m.Close)
	m.LoadRules()
	m.LoadServers()
	m.QueryAndSetStatus()
	return
}

func (m *ManagerWindow) Close(canceled *bool, reason walk.CloseReason) {
	*canceled = true
	m.MainWindow.Hide()
}

func (m *ManagerWindow) Add() {}

func (m *ManagerWindow) Hide() {
	m.MainWindow.Hide()
}

func (m *ManagerWindow) Show() {
	m.MainWindow.SetSize(walk.Size{400, 175})
	m.QueryAndSetStatus()
	m.MainWindow.Show()
}

func (m *ManagerWindow) Install() {
	conf, err := GetConfig("config.json")
	if err != nil {
		m.Error(err)
		return
	}
	exist, err := IsExistService(m.ServiceName)
	if err != nil {
		m.Error(err)
		return
	}
	if exist {
		return
	}
	if err := InstallService(m.ServiceName, m.ServiceDesc, []string{"-c", conf}); err != nil {
		m.Error(err)
	}
}

func (m *ManagerWindow) Remove() {
	exist, err := IsExistService(m.ServiceName)
	if err != nil {
		m.Error(err)
		return
	}
	if !exist {
		return
	}
	if err := RemoveService(m.ServiceName); err != nil {
		m.Error(err)
	}
}

func (m *ManagerWindow) Generate() {
	server := m.boxServer.Text()
	if server == "" {
		m.Error(errors.New("Please select a server"))
		return
	}
	mode := m.boxMode.Text()
	if mode == "" {
		m.Error(errors.New("Please select a mode"))
		return
	}
	apps, cidr, err := ParseRules(m.ruleMap[mode])
	if err != nil {
		m.Error(err)
		return
	}
	if err := Generate(server, apps, cidr); err != nil {
		m.Error(err)
		return
	}
}

func (m *ManagerWindow) Start() {
	running, err := IsRunningService(m.ServiceName)
	if err != nil {
		m.Error(err)
		return
	}
	if running {
		return
	}
	if err := StartService(m.ServiceName); err != nil {
		m.Error(err)
		return
	}
	time.Sleep(500 * time.Millisecond)
	m.QueryAndSetStatus()
}

func (m *ManagerWindow) Stop() {
	running, err := IsRunningService(m.ServiceName)
	if err != nil {
		m.Error(err)
		return
	}
	if !running {
		return
	}
	if err := ControlService(m.ServiceName, svc.Stop, svc.Stopped); err != nil {
		m.Error(err)
		return
	}
	m.QueryAndSetStatus()
}

func (m *ManagerWindow) LoadRules() {
	rules, err := GetRuleDir("rules")
	if err != nil {
		m.Error(err)
		return
	}
	m.ruleSlice, m.ruleMap, err = GetRules(rules)
	if err != nil {
		m.Error(err)
	}
	m.boxMode.SetModel(m.ruleSlice)
	return
}

type Server struct {
	Servers []string
}

func (m *ManagerWindow) LoadServers() {
	config, err := GetConfig("servers.json")
	if err != nil {
		m.Error(err)
		return
	}
	b, err := ioutil.ReadFile(config)
	if err != nil {
		m.Error(err)
		return
	}
	s := Server{}
	if err := json.Unmarshal(b, &s); err != nil {
		m.Error(err)
		return
	}
	m.serverSlice = s.Servers
	m.boxServer.SetModel(m.serverSlice)
	return
}

func (m *ManagerWindow) QueryAndSetStatus() {
	running, err := IsRunningService(m.ServiceName)
	if err != nil {
		m.Error(err)
		return
	}
	if running {
		m.itemStatus.SetText("Shadow is Running")
		return
	}
	m.itemStatus.SetText("Shadow is not Running")
}

func (m *ManagerWindow) About() {
	walk.MsgBox(m.MainWindow, "About", about, walk.MsgBoxIconInformation)
}

func (m *ManagerWindow) Error(err error) {
	walk.MsgBox(m.MainWindow, "Error", err.Error(), walk.MsgBoxIconError)
}

type Monitor struct {
	ManagerWindow
	ServiceName string
	ServiceDesc string

	mainWindow *walk.MainWindow
	notifyIcon *walk.NotifyIcon
	icon       *walk.Icon
}

func (m *Monitor) Run() (err error) {
	if m.mainWindow, err = walk.NewMainWindow(); err != nil {
		return
	}

	if m.notifyIcon, err = walk.NewNotifyIcon(m.mainWindow); err != nil {
		return
	}
	defer m.notifyIcon.Dispose()

	m.notifyIcon.SetToolTip("A Transparent Proxy for Windows, Linux and macOS")
	if m.icon, err = walk.NewIconFromResourceWithSize("$shadow.ico", walk.Size{16, 16}); err != nil {
		return
	}
	m.notifyIcon.SetIcon(m.icon)

	m.notifyIcon.MouseDown().Attach(m.mouseClicked)

	exitAction := walk.NewAction()
	if err = exitAction.SetText("E&xit"); err != nil {
		return
	}
	exitAction.Triggered().Attach(m.Exit)
	if err = m.notifyIcon.ContextMenu().Actions().Add(exitAction); err != nil {
		return
	}

	m.ManagerWindow.ServiceName = m.ServiceName
	m.ManagerWindow.ServiceDesc = m.ServiceDesc
	m.ManagerWindow.icon = m.icon
	if err = m.ManagerWindow.setup(); err != nil {
		return
	}
	m.notifyIcon.SetVisible(true)
	m.mainWindow.Run()
	return nil
}

func (m *Monitor) mouseClicked(x, y int, button walk.MouseButton) {
	if button == walk.LeftButton {
		m.ManagerWindow.Show()
	}
}

func (m *Monitor) Exit() {
	ControlService(m.ServiceName, svc.Stop, svc.Stopped)
	walk.App().Exit(0)
}
