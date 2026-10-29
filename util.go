package main

import "runtime"

func numCPU() int { return runtime.NumCPU() }

// buildRoutes derives the Caddy routing table from current state. Called after
// publishing so a brand-new address already carries its onion ID.
func (a *App) buildRoutes() []Route {
	addrs := map[string]Address{}
	for _, ad := range a.store.ListAddresses() {
		addrs[ad.ID] = ad
	}
	routes := []Route{}
	for _, s := range a.store.ListServices() {
		if !s.Enabled {
			continue
		}
		ad, ok := addrs[s.AddressID]
		if !ok || ad.OnionID == "" {
			continue
		}
		routes = append(routes, Route{
			OnionID: ad.OnionID, Target: s.Target,
			BasicUser: s.BasicUser, BasicHash: s.BasicHash, RateLimit: s.RateLimit,
		})
	}
	return routes
}
