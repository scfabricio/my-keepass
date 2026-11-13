package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	vault := NewVaultService()
	app := application.New(application.Options{
		Name:        "Meu Cofre",
		Description: "Gerenciador pessoal de senhas criptografadas",
		Services:    []application.Service{application.NewService(vault)},
		OnShutdown:  vault.LockVault,
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ApplicationShouldTerminateAfterLastWindowClosed: true,
		},
	})
	vault.app = app

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Meu Cofre",
		Width:            1100,
		Height:           760,
		MinWidth:         760,
		MinHeight:        560,
		BackgroundColour: application.NewRGB(17, 20, 25),
		URL:              "/",
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
