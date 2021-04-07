package main

func main() {
	a := App{}
	a.Initialize(
		//os.Getenv("APP_DB_USERNAME"),
		//os.Getenv("APP_DB_PASSWORD"),
		//os.Getenv("APP_DB_NAME"))
		"postgres",
		"123456",
		"postgres")

	a.Run(":8010")
}
