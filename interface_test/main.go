package main

import "db_demo/interface_test/gadget"

func PlayList(device gadget.TapePLayer, songs []string) {
	for _, song := range songs {
		device.Play(song)
	}
	device.Stop()
}

func main() {
	player := gadget.TapePLayer{}
	songs := []string{"A", "B", "C"}
	PlayList(player, songs)
}
