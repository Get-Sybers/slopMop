package main

type extra struct{}

func helper() {}

func main() { helper(); _ = extra{} }
