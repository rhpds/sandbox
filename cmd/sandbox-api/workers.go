package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	cc "github.com/rhpds/sandbox/internal/config"
	"github.com/rhpds/sandbox/internal/log"
	"github.com/rhpds/sandbox/internal/models"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/jackc/pgx/v4"
)

type Worker struct {
	// Postgres connection pool to subscribe/publish events
	Dbpool *pgxpool.Pool

	// Account provider to interact with the database
	AwsAccountProvider models.AwsAccountProvider

	// AWS client to manage the accounts
	StsClient *sts.Client
}

// AssumeRole gives back a set of temporary credentials to have access to the AWS account

func (w Worker) AssumeRole(account models.AwsAccount) (*sts.AssumeRoleOutput, error) {

	// Create the request
	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int32(900),
		RoleArn:         aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", account.AccountID, "OrganizationAccountAccessRole")),
		RoleSessionName: aws.String(fmt.Sprintf("session-%s", account.AccountID)),
	}

	// Send the request and get the response
	resp, err := w.StsClient.AssumeRole(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Execute executes a LifecycleResourceJob.
// It checks the resource type and the lifecycle action and execute the appropriate function
func (w Worker) Execute(j *models.LifecycleResourceJob) error {
	switch j.ResourceType {
	case "AwsSandbox", "AwsAccount", "aws_account":
		// Get the sandbox
		sandbox, err := w.AwsAccountProvider.FetchByName(j.ResourceName)
		if err != nil {
			log.Logger.Error("Error fetching sandbox", "error", err)
			return err
		}

		log.Logger.Debug("Got action", "action", j.Action)
		assume, err := w.AssumeRole(sandbox)
		if err != nil {
			return err
		}

		log.Logger.Debug("assume successful")
		switch j.Action {
		case "start":
			j.SetStatus("running")
			return sandbox.Start(assume.Credentials)
		case "stop":
			j.SetStatus("running")
			return sandbox.Stop(assume.Credentials)
		case "status":
			j.SetStatus("running")
			status, err := sandbox.Status(assume.Credentials, j)
			if err != nil {
				j.SetStatus("error")
				log.Logger.Error("Error getting status", "error", err)
			}
			log.Logger.Debug("Got status", "status", status)
			return err
		}
	}

	return nil
}

// consumeChannels is a goroutine that listens to the golang channels and processes the events
func (w Worker) consumeChannels(ctx context.Context, LifecycleResourceJobsStatusChannel chan string, LifecyclePlacementJobsStatusChannel chan string) {
WorkerLoop:
	for {
		select {
		case <-ctx.Done():
			log.Logger.Warn("Context cancelled, exiting consumeChannels worker")
			return
		case msg := <-LifecycleResourceJobsStatusChannel:
			id, err := strconv.Atoi(msg)
			if err != nil {
				log.Logger.Error("Error converting message to int", "error", err)
				continue WorkerLoop
			}
			job, err := models.GetLifecycleResourceJob(w.Dbpool, id)
			if err != nil {
				if err == pgx.ErrNoRows {
					log.Logger.Debug("Resource job not found", "job", job)
					continue WorkerLoop
				}
				log.Logger.Error("Error getting lifecycle resource job", "error", err)
				continue WorkerLoop
			}
			log.Logger.Debug("Got lifecycle resource job", "job", job)
			if job.Locality != cc.LocalityID && job.Locality != "any" {
				// log
				log.Logger.Debug("Job not for this locality", "job", job)

				// Sleep 2 seconds to give time to original worker to claim the job
				time.Sleep(2 * time.Second)

				// Check if it's still new

				job, err = models.GetLifecycleResourceJob(w.Dbpool, id)
				if err != nil {
					if err == pgx.ErrNoRows {
						log.Logger.Debug("Resource job not found", "job", job)
						continue WorkerLoop
					}
					log.Logger.Error("Error getting lifecycle placement job", "error", err)
					continue WorkerLoop
				}
			}

			switch job.Status {
			case "new":
				if err := job.Claim(); err != nil {
					if err == models.ErrNoClaim {
						log.Logger.Debug("Job already claimed", "job", job)
					} else {
						log.Logger.Error("Error claiming job", "error", err)
					}
					continue WorkerLoop
				}
				// New job arrived, let's process it
				job.SetStatus("initialized")

				err := w.Execute(job)
				if err != nil {
					job.SetStatus("error")
					log.Logger.Error("Error executing job", "error", err)
					continue WorkerLoop
				}
				job.SetStatus("success")
			}

		case msg := <-LifecyclePlacementJobsStatusChannel:
			id, err := strconv.Atoi(msg)
			if err != nil {
				log.Logger.Error("Error converting message to int", "error", err)
				continue WorkerLoop
			}
			job, err := models.GetLifecyclePlacementJob(w.Dbpool, id)
			if err != nil {
				if err == pgx.ErrNoRows {
					log.Logger.Debug("Placement job not found", "job", job)
					continue WorkerLoop
				}
				log.Logger.Error("Error getting lifecycle placement job", "error", err)
				continue WorkerLoop
			}

			log.Logger.Debug("notification placement job received", "job", job)
			if job.Locality != cc.LocalityID && job.Locality != "any" {
				// log
				log.Logger.Debug("Job not for this locality", "job", job)

				// Sleep 2 seconds to give time to original worker to claim the job
				time.Sleep(2 * time.Second)

				// Check if it's still new

				job, err = models.GetLifecyclePlacementJob(w.Dbpool, id)
				if err != nil {
					if err == pgx.ErrNoRows {
						log.Logger.Debug("Placement job not found", "job", job)
						continue WorkerLoop
					}
					log.Logger.Error("Error getting lifecycle placement job", "error", err)
					continue WorkerLoop
				}
			}

			switch job.Status {
			case "new":
				if err := job.Claim(); err != nil {
					if err == models.ErrNoClaim {
						log.Logger.Debug("Job already claimed", "job", job)
					} else {
						log.Logger.Error("Error claiming job", "error", err)
					}
					continue WorkerLoop
				}

				// New job arrived, let's process it
				job.SetStatus("initialized")
				placement, err := models.GetPlacement(w.Dbpool, job.PlacementID)

				if err != nil {
					log.Logger.Error("Error getting placement", "error", err)
					job.SetStatus("error")
					continue WorkerLoop
				}

				// Get all accounts in the placement
				if err := placement.LoadActiveResources(w.AwsAccountProvider); err != nil {
					log.Logger.Error("Error loading resources", "error", err, "placement", placement)
					job.SetStatus("error")
					continue WorkerLoop
				}
				log.Logger.Debug("Got placement", "placement", placement)

			ResourceLoop:
				for _, account := range placement.Resources {
					// Create a new LifecycleResourceJob for each account
					// Detect type of the resource using reflection
					switch account.(type) {
					case models.AwsAccount:
						awsAccount := account.(models.AwsAccount)
						log.Logger.Debug("Creating resource job for account", "account", awsAccount)

						lifecycleResourceJob := models.LifecycleResourceJob{
							ParentID:     job.ID,
							Locality:     cc.LocalityID,
							RequestID:    job.RequestID,
							ResourceType: awsAccount.Kind,
							ResourceName: awsAccount.Name,
							Action:       job.Action,
							Status:       "new",
							DbPool:       w.Dbpool,
						}

						if err := lifecycleResourceJob.Create(); err != nil {
							log.Logger.Error("Error creating lifecycle resource job", "error", err)
							job.SetStatus("error")
							continue ResourceLoop
						}
						log.Logger.Debug("Created resource job for account", "account", awsAccount, "job", lifecycleResourceJob)
					}
				}
				job.SetStatus("successfully_dispatched")
			}
		}
	}
}

func (w Worker) WatchLifecycleDBChannels(ctx context.Context) error {

	// Create channels for resource lifecycle events
	LifecycleResourceJobsStatusChannel := make(chan string)
	LifecyclePlacementJobsStatusChannel := make(chan string)

	// convert environment variable WORKERS to int
	workers, err := strconv.Atoi(os.Getenv("WORKERS"))
	if err != nil {
		log.Logger.Error("Error converting WORKERS to int", "error", err)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	// In case this goroutine stop, stop all workers and restart it
	defer func() {
		// Log that we are restarting
		log.Logger.Warn("Restarting worker WatchLifecycleDBChannels and its workers")
		cancel()
		// sleep for 5 seconds before restarting
		time.Sleep(5 * time.Second)

		go w.WatchLifecycleDBChannels(context.Background())
	}()

	conn, err := w.Dbpool.Acquire(context.Background())
	if err != nil {
		log.Logger.Error("Error acquiring connection", "error", err)
		return err
	}
	defer conn.Release()

	channels := []string{
		"lifecycle_placement_jobs_status_channel",
		"lifecycle_resource_jobs_status_channel",
	}
	for _, pgChan := range channels {
		_, err = conn.Exec(context.Background(), fmt.Sprintf("LISTEN %s", pgChan))
		if err != nil {
			log.Logger.Error("Error listening to the channel", "channel", pgChan, "error", err)
			return err
		}
		log.Logger.Info("Listening to channel", "channel", pgChan)
	}

	// Create go routines to listen to the Golang channels
	for i := 0; i < workers; i++ {
		go w.consumeChannels(ctx, LifecycleResourceJobsStatusChannel, LifecyclePlacementJobsStatusChannel)
	}

	for {
		notification, err := conn.Conn().WaitForNotification(context.Background())
		if err != nil {
			log.Logger.Error("Error while listening to the channel", "error", err)
			return err
		}

		log.Logger.Debug("Notification received", "PID", notification.PID, "Channel", notification.Channel, "Payload", notification.Payload)

		switch notification.Channel {
		case "lifecycle_placement_jobs_status_channel":
			LifecyclePlacementJobsStatusChannel <- notification.Payload

		case "lifecycle_resource_jobs_status_channel":
			LifecycleResourceJobsStatusChannel <- notification.Payload
		}
	}
}

// NewWorker creates a new worker
func NewWorker(baseHandler BaseHandler) Worker {

	cfg, err := config.LoadDefaultConfig(
		context.TODO(),
	)
	if err != nil {
		log.Logger.Error("Error loading config", "error", err)
		os.Exit(1)
	}

	// Create new STS client
	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Credentials = credentials.NewStaticCredentialsProvider(
			os.Getenv("ASSUMEROLE_AWS_ACCESS_KEY_ID"),
			os.Getenv("ASSUMEROLE_AWS_SECRET_ACCESS_KEY"),
			"",
		)
	})

	return Worker{
		Dbpool:          baseHandler.dbpool,
		AwsAccountProvider: baseHandler.awsAccountProvider,
		StsClient:       stsClient,
	}
}
