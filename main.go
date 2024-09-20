package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/ipfs/go-cid"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	record "github.com/libp2p/go-libp2p-record"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/client"
	"github.com/libp2p/go-libp2p/p2p/protocol/circuitv2/relay"
	"github.com/multiformats/go-multiaddr"
	"github.com/multiformats/go-multihash"
)

var (
	server          = "s5"
	server_addr     = 61005
	relay_node_addr = "/ip4/130.245.173.222/tcp/4000/p2p/12D3KooWSMDFN5DeFADosuV7UEwjHWQv1ioLEUqgzjGjxYQzxFX6"
	//"/ip4/130.245.173.221/tcp/4001/p2p/12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN"
	bootstrap_node_addr = "/ip4/130.245.173.222/tcp/61000/p2p/12D3KooWPcfGdBCrdxX9nqGAdPAdkPMqfKEDjbZWGA4UFBJuY4rP"
	globalCtx           context.Context
)

func generatePrivateKeyFromSeed(seed []byte) (crypto.PrivKey, error) {
	// Generate deterministic key material
	hash := sha256.Sum256(seed)
	// Create an Ed25519 private key from the hash
	privKey, _, err := crypto.GenerateEd25519Key(
		bytes.NewReader(hash[:]),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privKey, nil
}

func isPortAvailable(port int) bool {
	address := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

func createNode() (host.Host, *dht.IpfsDHT, error) {
	ctx := context.Background()
	node_addr := server_addr
	seed := []byte(server)
	for !isPortAvailable(node_addr) {
		node_addr++
	}
	portStr := strconv.Itoa(node_addr)

	customAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/" + portStr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse multiaddr: %w", err)
	}
	privKey, err := generatePrivateKeyFromSeed(seed)
	if err != nil {
		log.Fatal(err)
	}
	relayAddr, err := multiaddr.NewMultiaddr(relay_node_addr)
	if err != nil {
		log.Fatalf("Failed to create relay multiaddr: %v", err)
	}

	// Convert the relay multiaddress to AddrInfo
	relayInfo, err := peer.AddrInfoFromP2pAddr(relayAddr)
	if err != nil {
		log.Fatalf("Failed to create AddrInfo from relay multiaddr: %v", err)
	}

	node, err := libp2p.New(
		libp2p.ListenAddrs(customAddr),
		libp2p.Identity(privKey),
		libp2p.NATPortMap(),
		libp2p.EnableNATService(),
		libp2p.EnableAutoRelayWithStaticRelays([]peer.AddrInfo{*relayInfo}),
		libp2p.EnableRelayService(),
		// libp2p.EnableAutoRelay(),
		// libp2p.StaticRelays(staticRelays),
	)

	if err != nil {
		return nil, nil, err
	}
	_, err = relay.New(node)
	if err != nil {
		log.Printf("Failed to instantiate the relay: %v", err)
	}

	dhtRouting, err := dht.New(ctx, node, dht.Mode(dht.ModeServer))
	if err != nil {
		return nil, nil, err
	}
	namespacedValidator := record.NamespacedValidator{
		"myapp": &CustomValidator{}, // Add a custom validator for the "myapp" namespace
	}
	// Configure the DHT to use the custom validator
	dhtRouting.Validator = namespacedValidator

	err = dhtRouting.Bootstrap(ctx)
	if err != nil {
		return nil, nil, err
	}
	fmt.Println("DHT bootstrap complete.")

	// Set up notifications for new connections
	node.Network().Notify(&network.NotifyBundle{
		ConnectedF: func(n network.Network, conn network.Conn) {
			fmt.Printf("New peer connected: %s\n", conn.RemotePeer().String())
		},
	})

	return node, dhtRouting, nil
}

func connectToPeer(node host.Host, peerAddr string) {
	addr, err := multiaddr.NewMultiaddr(peerAddr)
	if err != nil {
		log.Printf("Failed to parse peer address: %s", err)
		return
	}

	info, err := peer.AddrInfoFromP2pAddr(addr)
	if err != nil {
		log.Printf("Failed to get AddrInfo from address: %s", err)
		return
	}

	node.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
	err = node.Connect(context.Background(), *info)
	if err != nil {
		log.Printf("Failed to connect to peer: %s", err)
		return
	}

	fmt.Println("Connected to:", info.ID)
}

// func findPeer(dht *dht.IpfsDHT, peerID peer.ID) {
// 	ctx := context.Background()
// 	_, err := dht.FindPeer(ctx, peerID)
// 	if err != nil {
// 		log.Printf("Failed to find peer: %s", err)
// 		return
// 	}
// 	fmt.Println("Found peer:", peerID)
// }

// func exchangePeers(node host.Host, newPeer peer.ID) {
// 	knownPeers := node.Peerstore().Peers()
// 	var peerInfos []string
// 	for _, peer := range knownPeers {
// 		if peer != newPeer && peer != node.ID() {
// 			addrs := node.Peerstore().Addrs(peer)
// 			for _, addr := range addrs {
// 				peerAddr := addr.String() + "/p2p/" + peer.String()
// 				peerInfos = append(peerInfos, peerAddr)
// 			}
// 		}
// 	}
// 	// Send peer info to the new peer
// 	s, err := node.NewStream(context.Background(), newPeer, "/peer-exchange/1.0.0")
// 	if err != nil {
// 		log.Printf("Failed to open stream to %s: %s", newPeer, err)
// 		return
// 	}
// 	defer s.Close()
// 	for _, info := range peerInfos {
// 		_, err := s.Write([]byte(info + "\n"))
// 		if err != nil {
// 			log.Printf("Failed to send peer info to %s: %s", newPeer, err)
// 			return
// 		}
// 	}
// 	fmt.Printf("Shared %d peers with %s\n", len(peerInfos), newPeer.String())
// }

// func handlePeerExchange(node host.Host) {
// 	node.SetStreamHandler("/peer-exchange/1.0.0", func(s network.Stream) {
// 		defer s.Close()
// 		buf := bufio.NewReader(s)
// 		for {
// 			peerAddr, err := buf.ReadString('\n')
// 			if err != nil {
// 				if err != io.EOF {
// 					log.Printf("Error reading from stream: %s", err)
// 				}
// 				return
// 			}
// 			connectToPeerUsingRelay(node, peerAddr)
// 			// peerAddr = strings.TrimSpace(peerAddr)
// 			// // Parse the peer address
// 			// addr, err := multiaddr.NewMultiaddr(peerAddr)
// 			// if err != nil {
// 			// 	log.Printf("Invalid peer address received: %s", err)
// 			// 	continue
// 			// }
// 			// // Extract the peer ID from the address
// 			// info, err := peer.AddrInfoFromP2pAddr(addr)
// 			// if err != nil {
// 			// 	log.Printf("Failed to extract peer info: %s", err)
// 			// 	continue
// 			// }
// 			// // Add the peer to the peerstore
// 			// node.Peerstore().AddAddrs(info.ID, info.Addrs, peerstore.PermanentAddrTTL)
// 			// // Optionally, try to connect to the new peer
// 			// if err := node.Connect(context.Background(), *info); err != nil {
// 			// 	log.Printf("Failed to connect to peer %s: %s", info.ID, err)
// 			// } else {
// 			// 	fmt.Printf("Connected to new peer: %s\n", info.ID)
// 			// }
// 		}
// 	})
// }

func handlePeerExchange1(node host.Host) {
	node.SetStreamHandler("/peer-exchange/1.0.0", func(s network.Stream) {
		defer s.Close()

		buf := bufio.NewReader(s)
		peerAddr, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Printf("error reading from stream: %v", err)
			}
		}
		peerAddr = strings.TrimSpace(peerAddr)
		var data map[string]interface{}
		err = json.Unmarshal([]byte(peerAddr), &data)
		if err != nil {
			fmt.Printf("error unmarshaling JSON: %v", err)
		}
		if knownPeers, ok := data["known_peers"].([]interface{}); ok {
			for _, peer := range knownPeers {
				fmt.Println("Peer:")
				if peerMap, ok := peer.(map[string]interface{}); ok {
					if peerID, ok := peerMap["peer_id"].(string); ok {
						if string(peerID) != "12D3KooWSMDFN5DeFADosuV7UEwjHWQv1ioLEUqgzjGjxYQzxFX6" {
							connectToPeerUsingRelay(node, peerID)
						}
					}
					// if peerAddr, ok := peerMap["peer_addr"].(string); ok {
					// 	connectToPeerUsingRelay(node, peerAddr)
					// }
				}
			}
		}
	})
}

// func announceToDHT(ctx context.Context, dht *dht.IpfsDHT, node host.Host) {
// 	backoff := time.Second
// 	maxBackoff := time.Hour
// 	for {
// 		err := dht.Provide(ctx, peer.ToCid(node.ID()), true)
// 		if err != nil {
// 			log.Printf("Error providing to DHT: %s", err)
// 			backoff = min(backoff*2, maxBackoff)
// 		} else {
// 			backoff = time.Hour // Reset to 1 hour on success
// 		}
// 		time.Sleep(backoff)
// 	}
// }

// func discoverPeers(ctx context.Context, dht *dht.IpfsDHT, node host.Host) {
// 	// Create a unique CID for discovery
// 	discoveryCID := peer.ToCid(node.ID())
// 	for {
// 		fmt.Println("Searching for peers...")
// 		peerChan := dht.FindProvidersAsync(ctx, discoveryCID, 10)
// 		for p := range peerChan {
// 			if p.ID != node.ID() {
// 				err := node.Connect(ctx, p)
// 				if err != nil {
// 					log.Printf("Error connecting to discovered peer %s: %s", p.ID, err)
// 				} else {
// 					fmt.Printf("Connected to discovered peer: %s\n", p.ID)
// 				}
// 			}
// 		}
// 		// Provide our own CID to the network
// 		err := dht.Provide(ctx, discoveryCID, true)
// 		if err != nil {
// 			log.Printf("Error providing to DHT: %s", err)
// 		}
// 		time.Sleep(5 * time.Minute)
// 	}
// }

func connectToPeerUsingRelay(node host.Host, peerAddrStr string) {
	ctx := globalCtx
	peerAddrStr = strings.TrimSpace(peerAddrStr)
	peerAddr, err := multiaddr.NewMultiaddr(relay_node_addr)
	if err != nil {
		log.Printf("Failed to create relay multiaddr: %v", err)
	}
	peerMultiaddr := peerAddr.Encapsulate(multiaddr.StringCast("/p2p-circuit/p2p/" + peerAddrStr))
	relayedAddrInfo, err := peer.AddrInfoFromP2pAddr(peerMultiaddr)
	if err != nil {
		log.Println("Failed to get relayed AddrInfo: %w", err)
		return
	}
	// Connect to the peer through the relay
	err = node.Connect(ctx, *relayedAddrInfo)
	if err != nil {
		log.Println("Failed to connect to peer through relay: %w", err)
		return
	}

	fmt.Printf("Connected to peer via relay: %s\n", peerAddrStr)

}

// Not useful can be removed -->
// func monitorPeers(node host.Host) {
// 	knownPeers := make(map[peer.ID]bool)
// 	for {
// 		time.Sleep(5 * time.Second)
// 		for _, peerID := range node.Network().Peers() {
// 			if !knownPeers[peerID] {
// 				fmt.Printf("New peer in peerstore: %s\n", peerID.String())
// 				knownPeers[peerID] = true
// 			}
// 		}
// 	}
// }

func main() {
	node, dht, err := createNode()
	if err != nil {
		log.Fatalf("Failed to create node: %s", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	globalCtx = ctx

	fmt.Println("Node multiaddresses:", node.Addrs())
	fmt.Println("Node Peer ID:", node.ID())

	connectToPeer(node, relay_node_addr)     // connect to relay node
	connectToPeer(node, bootstrap_node_addr) // connect to bootstrap node

	handlePeerExchange1(node)

	// go announceToDHT(ctx, dht, node)
	// go discoverPeers(ctx, dht, node)
	// go monitorPeers(node)
	// go findProviders(dht, "exampleKey")

	if len(os.Args) > 1 {
		// peerAddr := os.Args[1]
		// connectToPeer(node, peerAddr)

		// peerInfo, err := peer.AddrInfoFromString(peerAddr)
		// if err != nil {
		// 	log.Printf("Failed to extract peer ID: %s", err)
		// } else {
		// 	findPeer(dht, peerInfo.ID)
		// }
	}
	makeReservation(node)
	go handleInput(ctx, dht)

	defer node.Close()

	select {}
}

func handleInput(ctx context.Context, dht *dht.IpfsDHT) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("User Input \n ")
	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n') // Read input from keyboard
		input = strings.TrimSpace(input)    // Trim any trailing newline or spaces
		args := strings.Split(input, " ")
		if len(args) < 1 {
			fmt.Println("No command provided")
			continue
		}
		command := args[0]
		command = strings.ToUpper(command)
		switch command {
		case "GET":
			if len(args) < 2 {
				fmt.Println("Expected key")
				continue
			}
			key := args[1]
			dhtKey := "/myapp/" + key
			res, err := dht.GetValue(ctx, dhtKey)
			if err != nil {
				fmt.Printf("Failed to get record: %v\n", err)
				continue
			}
			fmt.Printf("Record: %s\n", res)

		case "GET_PROVIDERS":
			if len(args) < 2 {
				fmt.Println("Expected key")
				continue
			}
			key := args[1]
			data := []byte(key)
			hash := sha256.Sum256(data)
			mh, err := multihash.EncodeName(hash[:], "sha2-256")
			if err != nil {
				fmt.Printf("Error encoding multihash: %v\n", err)
				continue
			}
			c := cid.NewCidV1(cid.Raw, mh)
			providers := dht.FindProvidersAsync(ctx, c, 20)

			fmt.Println("Searching for providers...")
			for p := range providers {
				if p.ID == peer.ID("") {
					break
				}
				fmt.Printf("Found provider: %s\n", p.ID.String())
				for _, addr := range p.Addrs {
					fmt.Printf(" - Address: %s\n", addr.String())
				}
			}

		case "PUT":
			if len(args) < 3 {
				fmt.Println("Expected key and value")
				continue
			}
			log.Println(args[1])
			key := args[1]
			value := args[2]
			dhtKey := "/myapp/" + key
			err := dht.PutValue(ctx, dhtKey, []byte(value))
			if err != nil {
				fmt.Printf("Failed to put record: %v\n", err)
				continue
			}
			provideKey(ctx, dht, key)
			fmt.Println("Record stored successfully")

		case "PUT_PROVIDER":
			if len(args) < 2 {
				fmt.Println("Expected key")
				continue
			}
			key := args[1]
			provideKey(ctx, dht, key)

			// data := []byte(key)
			// hash := sha256.Sum256(data)
			// mh, err := multihash.EncodeName(hash[:], "sha2-256")
			// if err != nil {
			// 	fmt.Printf("Error encoding multihash: %v\n", err)
			// 	continue
			// }
			// c := cid.NewCidV1(cid.Raw, mh)
			// err = dht.Provide(ctx, c, true)
			// if err != nil {
			// 	fmt.Printf("Failed to start providing key: %v\n", err)
			// 	continue
			// }
			// fmt.Println("Started providing key")

		default:
			fmt.Println("Expected GET, GET_PROVIDERS, PUT or PUT_PROVIDER")
		}
	}
}

func provideKey(ctx context.Context, dht *dht.IpfsDHT, key string) error {
	data := []byte(key)
	hash := sha256.Sum256(data)
	mh, err := multihash.EncodeName(hash[:], "sha2-256")
	if err != nil {
		return fmt.Errorf("error encoding multihash: %v", err)
	}
	c := cid.NewCidV1(cid.Raw, mh)

	// Start providing the key
	err = dht.Provide(ctx, c, true)
	if err != nil {
		return fmt.Errorf("failed to start providing key: %v", err)
	}

	fmt.Println("Started providing key")
	return nil
}

func makeReservation(node host.Host) {
	ctx := globalCtx
	relayAddr, err := multiaddr.NewMultiaddr(relay_node_addr)
	// relayMultiaddr := relayAddr.Encapsulate(multiaddr.StringCast("/p2p-circuit"))
	if err != nil {
		log.Fatalf("Failed to create relay multiaddr: %v", err)
	}
	relayInfo, err := peer.AddrInfoFromP2pAddr(relayAddr)
	if err != nil {
		log.Fatalf("Failed to create AddrInfo from relay multiaddr: %v", err)
	}
	log.Println("reserve ", relayInfo)
	_, err = client.Reserve(ctx, node, *relayInfo)
	if err != nil {
		log.Fatalf("Failed to make reservation on relay: %v", err)
	}
	fmt.Printf("Reservation successfull \n")
}
