package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/peerclaw/peerclaw-agent/security"
)

const defaultTrustStorePath = "trust.json"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	storePath := os.Getenv("PEERCLAW_TRUST_STORE")
	if storePath == "" {
		storePath = defaultTrustStorePath
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "list":
		cmdList(storePath)
	case "verify":
		cmdVerify(storePath, args)
	case "pin":
		cmdPin(storePath, args)
	case "revoke":
		cmdRevoke(storePath, args)
	case "export":
		cmdExport(storePath)
	case "import":
		cmdImport(storePath, args)
	case "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `peerclaw-trust - manage PeerClaw peer trust relationships

Usage:
  peerclaw-trust <command> [options]

Commands:
  list                   List all trust entries
  verify <pubkey>        Mark a peer as explicitly verified
  pin <pubkey>           Pin a peer (highest trust level)
  revoke <pubkey>        Block a peer
  export                 Export trust store to stdout as JSON
  import <file>          Import trust entries from a JSON file

Environment:
  PEERCLAW_TRUST_STORE   Path to trust store file (default: trust.json)
`)
}

func loadStore(path string) *security.TrustStore {
	ts := security.NewTrustStore()
	if err := ts.LoadFromFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "error loading trust store: %v\n", err)
		os.Exit(1)
	}
	return ts
}

func saveStore(ts *security.TrustStore, path string) {
	if err := ts.SaveToFile(path); err != nil {
		fmt.Fprintf(os.Stderr, "error saving trust store: %v\n", err)
		os.Exit(1)
	}
}

func cmdList(storePath string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "output as JSON")
	_ = fs.Parse(os.Args[2:])

	ts := loadStore(storePath)
	entries := ts.ListEntries()

	if *jsonOutput {
		data, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(data))
		return
	}

	if len(entries) == 0 {
		fmt.Println("No trust entries.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PUBLIC KEY\tLEVEL\tALIAS\tFIRST SEEN\tLAST SEEN")
	for _, e := range entries {
		alias := e.Alias
		if alias == "" {
			alias = "-"
		}
		lastSeen := e.LastSeen
		if lastSeen == "" {
			lastSeen = "-"
		}
		pk := e.PublicKey
		if len(pk) > 16 {
			pk = pk[:12] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			pk,
			security.TrustLevelString(e.Level),
			alias,
			e.FirstSeen,
			lastSeen,
		)
	}
	w.Flush()
}

func cmdVerify(storePath string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: peerclaw-trust verify <pubkey>")
		os.Exit(1)
	}
	ts := loadStore(storePath)
	ts.SetTrust(args[0], security.TrustVerified)
	saveStore(ts, storePath)
	fmt.Printf("Peer %s marked as verified.\n", truncateKey(args[0]))
}

func cmdPin(storePath string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: peerclaw-trust pin <pubkey>")
		os.Exit(1)
	}
	ts := loadStore(storePath)
	ts.SetTrust(args[0], security.TrustPinned)
	saveStore(ts, storePath)
	fmt.Printf("Peer %s pinned.\n", truncateKey(args[0]))
}

func cmdRevoke(storePath string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: peerclaw-trust revoke <pubkey>")
		os.Exit(1)
	}
	ts := loadStore(storePath)
	ts.SetTrust(args[0], security.TrustBlocked)
	saveStore(ts, storePath)
	fmt.Printf("Peer %s blocked.\n", truncateKey(args[0]))
}

func cmdExport(storePath string) {
	ts := loadStore(storePath)
	data, err := ts.Export()
	if err != nil {
		fmt.Fprintf(os.Stderr, "export error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}

func cmdImport(storePath string, args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: peerclaw-trust import <file>")
		os.Exit(1)
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read file: %v\n", err)
		os.Exit(1)
	}
	ts := loadStore(storePath)
	if err := ts.Import(data); err != nil {
		fmt.Fprintf(os.Stderr, "import error: %v\n", err)
		os.Exit(1)
	}
	saveStore(ts, storePath)
	fmt.Println("Trust entries imported successfully.")
}

func truncateKey(key string) string {
	if len(key) > 16 {
		return key[:12] + "..."
	}
	return key
}
