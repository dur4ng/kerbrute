package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

type State struct {
	NamesIndex    int
	SurnamesIndex int
	FormatsIndex  int
}

const stateFile = "program_state.json"

var state State

var userEnumCommand = &cobra.Command{
	Use:   "userenum [flags] file <username_wordlist>\n  kerbrute userenum [flags] dynamic <names_wordlist> <surnames_wordlist>",
	Short: "Enumerate valid domain usernames via Kerberos",
	Long: `Will enumerate valid usernames from a list by constructing AS-REQs to requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Valid usernames will be displayed on stdout.`,
	Args:   cobra.MaximumNArgs(4),
	PreRun: setupSession,
	Run:    userEnum,
}

func init() {
	rootCmd.AddCommand(userEnumCommand)
}

func userEnum(cmd *cobra.Command, args []string) {
	switch args[0] {
	case "file":
		usernamelist := args[1]
		completionChan := make(chan struct{})
		usersChan := make(chan string, threads)
		defer cancel()

		var wg sync.WaitGroup
		wg.Add(threads)

		var scanner *bufio.Scanner
		if usernamelist != "-" {
			file, err := os.Open(usernamelist)
			if err != nil {
				logger.Log.Error(err.Error())
				return
			}
			defer file.Close()
			scanner = bufio.NewScanner(file)
		} else {
			scanner = bufio.NewScanner(os.Stdin)
		}

		for i := 0; i < threads; i++ {
			go makeEnumWorker(ctx, usersChan, &wg, completionChan)
		}

		start := time.Now()

	Scan:
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				break Scan
			default:
				usernameline := scanner.Text()
				username, err := util.FormatUsername(usernameline)
				if err != nil {
					logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
					continue
				}
				time.Sleep(time.Duration(delay) * time.Millisecond)
				usersChan <- username
			}
		}
		close(usersChan)
		wg.Wait()

		finalCount := atomic.LoadInt32(&counter)
		finalSuccess := atomic.LoadInt32(&successes)
		logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

		if err := scanner.Err(); err != nil {
			logger.Log.Error(err.Error())
		}
	case "dynamic":
		namelistFile := args[1]
		surnamelistFile := args[2]
		formatLevel := args[3]

		formats_big := []string{
			"<name>",
			"<name><surname>",
			"<name>.<surname>",
			"<name>_<surname>",
			"<name>-<surname>",
			"<firtsletter_name><surname>",
			"<firtsletter_name>.<surname>",
			"<firtsletter_name>_<surname>",
			"<firtsletter_name>-<surname>",
			"<name><firtsletter_surname>",
			"<name>.<firtsletter_surname>",
			"<name>_<firtsletter_surname>",
			"<name>-<firtsletter_surname>",
			"<name><surname><surname>",
			"<name>.<surname>.<surname>",
			"<name>_<surname>_<surname>",
			"<name>-<surname>_<surname>",
			"<firtsletter_name><surname><surname>",
			"<firtsletter_name>.<surname>.<surname>",
			"<firtsletter_name>_<surname>_<surname>",
			"<firtsletter_name>-<surname>_<surname>",
			"<firtsletter_name><name><firtsletter_surname>",
		}
		formats_small := []string{
			"<name>",
			"<name><surname>",
			"<firtsletter_name><surname>",
			"<name><firtsletter_surname>",
			"<firtsletter_name><name><firtsletter_surname>",
		}
		var formats []string
		switch formatLevel {
		case "big":
			formats = formats_big
		case "small":
			formats = formats_small
		default:
		}
		names, err := readLines(namelistFile)
		if err != nil {
			logger.Log.Fatalf("Invalid names list!\n")
			os.Exit(1)
		}
		surnames, err := readLines(surnamelistFile)
		if err != nil {
			logger.Log.Fatalf("Invalid surnames list!\n")
			os.Exit(1)
		}

		completionChan := make(chan struct{})
		usersChan := make(chan string, threads)
		//defer cancel()

		var wg sync.WaitGroup
		wg.Add(threads)

		for i := 0; i < threads; i++ {
			go makeEnumWorker(ctx, usersChan, &wg, completionChan)
		}

		start := time.Now()
		go setupSignalHandler()

		loadState(&state)

		/*
			for _, name := range names {
				for _, surname := range surnames {
					for _, format := range formats {
						username := format
						username = replacePlaceholder(username, "<name>", name)
						username = replacePlaceholder(username, "<surname>", surname)
						username = replacePlaceholder(username, "<firtsletter_name>", string(name[0]))
						username = replacePlaceholder(username, "<firtsletter_surname>", string(surname[0]))
						formatUsername, err := util.FormatUsername(username)
						if err != nil {
							logger.Log.Debugf("[!] %q - %v", username, err.Error())
							continue
						}

						time.Sleep(time.Duration(delay) * time.Millisecond)
						usersChan <- formatUsername
					}
				}
			}*/
		for namesIndex := state.NamesIndex; namesIndex < len(names); namesIndex++ {
			//var usernames []string
			for surnamesIndex := state.SurnamesIndex; surnamesIndex < len(surnames); surnamesIndex++ {
				for formatsIndex := state.FormatsIndex; formatsIndex < len(formats); formatsIndex++ {
					username := formats[formatsIndex]
					username = replacePlaceholder(username, "<name>", names[namesIndex])
					username = replacePlaceholder(username, "<surname>", surnames[surnamesIndex])
					username = replacePlaceholder(username, "<firtsletter_name>", string(names[namesIndex][0]))
					username = replacePlaceholder(username, "<firtsletter_surname>", string(surnames[surnamesIndex][0]))
					formatUsername, err := util.FormatUsername(username)

					if err != nil {
						logger.Log.Debugf("[!] %q - %v", username, err.Error())
						continue
					}

					//time.Sleep(time.Duration(delay) * time.Millisecond)
					usersChan <- formatUsername
					//usernames = append(usernames, formatUsername)

					state.NamesIndex = namesIndex
					state.SurnamesIndex = surnamesIndex
					state.FormatsIndex = formatsIndex
				}
				state.FormatsIndex = 0 // Reset formatsIndex after inner loop
			}
			state.SurnamesIndex = 0 // Reset surnamesIndex after middle loop
		}
		close(usersChan)
		wg.Wait()

		finalCount := atomic.LoadInt32(&counter)
		finalSuccess := atomic.LoadInt32(&successes)
		logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())

		<-completionChan
	case "resume":
		// Load the state from a file if it exists.
		if err := loadState(&state); err != nil {
			logger.Log.Error("Not possible to load state!")
			os.Exit(1)
		}
		//TODO
	default:
		logger.Log.Error("Not available module!")
		os.Exit(1)
	}

}

func readLines(fileLocation string) ([]string, error) {
	file, err := os.Open(fileLocation)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	namesSlice := make([]string, 0)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		namesSlice = append(namesSlice, scanner.Text())
	}

	return namesSlice, nil
}

func replacePlaceholder(username, placeholder, replacement string) string {
	return strings.ReplaceAll(username, placeholder, replacement)
}

func loadState(state *State) error {
	file, err := os.Open("state.json")
	if err != nil {
		logger.Log.Info("Not state file found, new scan...")
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(state)
}

func saveState(state State) error {
	file, err := os.Create("state.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(state)
}

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		// Handle Ctrl+C signal here.
		// Save the state to a file.
		if err := saveState(state); err != nil {
			logger.Log.Error("Not available module!")
			os.Exit(1)
		}
		logger.Log.Info("State saved")
		os.Exit(1) // Exit gracefully.
	}()
}
