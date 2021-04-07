package gadget

import "fmt"

type TapePLayer struct {
	Batteries string
}

func (t TapePLayer) Play(song string) {
	fmt.Println("Song ... ", song)
}

func (t TapePLayer) Stop() {
	fmt.Println("Stop ... ")
}

type TapeRecorder struct {
	Batteries string
}

func (t TapeRecorder) Play(song string) {
	fmt.Println("Song ... ", song)
}

func (t TapeRecorder) Stop() {
	fmt.Println("Stop ... ")
}
