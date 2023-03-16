package dynamodb
import (
	"os"
	"log"
)

func CheckEnv() {
	if os.Getenv("AWS_PROFILE") == "" &&  os.Getenv("AWS_ACCESS_KEY_ID") == "" {
		log.Fatal("You must define env var AWS_PROFILE or AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY")
	}
	if os.Getenv("AWS_PROFILE") != "" &&  os.Getenv("AWS_ACCESS_KEY_ID") != "" {
		log.Fatal("You must chose between AWS_PROFILE and AWS_ACCESS_KEY_ID")
	}
	if os.Getenv("AWS_REGION") == "" {
		os.Setenv("AWS_REGION", "us-east-1")
	}
	if os.Getenv("dynamodb_table") == "" {
		os.Setenv("dynamodb_table", "accounts-dev")
	}
}
