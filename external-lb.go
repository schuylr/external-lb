package main

import (
	"fmt"
	"github.com/Sirupsen/logrus"
	"github.com/rancher/external-lb/model"
)

type Op int

const (
	ADD Op = iota
	REMOVE
	UPDATE
)

func UpdateProviderLBConfigs(metadataConfigs map[string]model.LBConfig) (map[string]model.LBConfig, error) {
	providerConfigs, err := getProviderLBConfigs()
	if err != nil {
		return nil, fmt.Errorf("Failed to get LB configs from provider: %v", err)
	}

	removeExtraConfigs(metadataConfigs, providerConfigs)
	updated := addMissingConfigs(metadataConfigs, providerConfigs)
	updated_ := updateExistingConfigs(metadataConfigs, providerConfigs)
	for k, v := range updated_ {
		if _, ok := updated[k]; !ok {
			updated[k] = v
		}
	}

	return updated, nil
}

func getProviderLBConfigs() (map[string]model.LBConfig, error) {
	allConfigs, err := provider.GetLBConfigs()
	if err != nil {
		return nil, err
	}

	rancherConfigs := make(map[string]model.LBConfig, len(allConfigs))
	for _, config := range allConfigs {
		rancherConfigs[config.EndpointName] = config
	}

	logrus.Debugf("LBConfigs from provider: %v", allConfigs)
	return rancherConfigs, nil
}

func removeExtraConfigs(metadataConfigs, providerConfigs map[string]model.LBConfig) map[string]model.LBConfig {
	var toRemove []model.LBConfig
	for key := range providerConfigs {
		if _, ok := metadataConfigs[key]; !ok {
			toRemove = append(toRemove, providerConfigs[key])
		}
	}

	if len(toRemove) == 0 {
		logrus.Debug("No LB configs to remove")
	} else {
		logrus.Infof("LB configs to remove: %d", len(toRemove))
	}

	return updateProvider(toRemove, REMOVE)
}

func addMissingConfigs(metadataConfigs, providerConfigs map[string]model.LBConfig) map[string]model.LBConfig {
	var toAdd []model.LBConfig
	for key := range metadataConfigs {
		if _, ok := providerConfigs[key]; !ok {
			toAdd = append(toAdd, metadataConfigs[key])
		}
	}
	if len(toAdd) == 0 {
		logrus.Debug("No LB configs to add")
	} else {
		logrus.Infof("LB configs to add: %d", len(toAdd))
	}

	return updateProvider(toAdd, ADD)
}

func updateExistingConfigs(metadataConfigs, providerConfigs map[string]model.LBConfig) map[string]model.LBConfig {
	var toUpdate []model.LBConfig
	for key := range metadataConfigs {
		if _, ok := providerConfigs[key]; ok {
			mLBConfig := metadataConfigs[key]
			pLBConfig := providerConfigs[key]

			if !checkEqualFrontends(mLBConfig.Frontends, pLBConfig.Frontends) {
				logrus.Debugf("LB config for endpoint %s needs to be updated", key)
				toUpdate = append(toUpdate, metadataConfigs[key])
			} else {
				logrus.Debugf("LB config for endpoint %s is already up to date", key)
			}
		}
	}

	if len(toUpdate) == 0 {
		logrus.Debug("No LB configs to update")
	} else {
		logrus.Infof("LB configs to update: %d", len(toUpdate))
	}

	return updateProvider(toUpdate, UPDATE)
}

func updateProvider(toChange []model.LBConfig, op Op) map[string]model.LBConfig {
	// map of FQDN -> LBConfig
	updateFqdn := make(map[string]model.LBConfig)
	for _, value := range toChange {
		switch op {
		case ADD:
			logrus.Infof("Adding LB config: %v", value)
			fqdn, err := provider.AddLBConfig(value)
			if err != nil {
				logrus.Errorf("Failed to add LB config for endpoint %s: %v", value.EndpointName, err)
			} else if fqdn != "" {
				updateFqdn[fqdn] = value
			}
		case REMOVE:
			logrus.Infof("Removing LB config: %v", value)
			if err := provider.RemoveLBConfig(value); err != nil {
				logrus.Errorf("Failed to remove LB config for endpoint %s: %v", value.EndpointName, err)
			}
		case UPDATE:
			logrus.Infof("Updating LB config: %v", value)
			fqdn, err := provider.UpdateLBConfig(value)
			if err != nil {
				logrus.Errorf("Failed to update LB config for endpoint %s: %v", value.EndpointName, err)
			} else if fqdn != "" {
				updateFqdn[fqdn] = value
			}
		}
	}

	return updateFqdn
}

func checkEqualFrontends(x, y []model.LBFrontend) bool {
	if len(x) != len(y) {
		return false
	}

	// create a map of port->frontend
	diff := make(map[int64]model.LBFrontend, len(x))
	for _, feX := range x {
		diff[feX.Port] = feX
	}

	for _, feY := range y {
		// if there is no frontend with matching port, bail out early
		if _, ok := diff[feY.Port]; !ok {
			return false
		}

		// check if frontend properties have changed
		feX := diff[feY.Port]
		if feX.Protocol != feY.Protocol || feX.Certificate != feY.Certificate {
			return false
		}

		if !checkEqualTargetPools(feX.TargetPools, feY.TargetPools) {
			return false
		}

		delete(diff, feY.Port)
	}

	if len(diff) == 0 {
		return true
	}

	return false
}

func checkEqualTargetPools(x, y []model.LBTargetPool) bool {
	if len(x) != len(y) {
		return false
	}

	// create a map of name->target pool
	diff := make(map[string]model.LBTargetPool, len(x))
	for _, tpX := range x {
		diff[tpX.Name] = tpX
	}

	for _, tpY := range y {
		// if there is no target pool with matching name, bail out early
		if _, ok := diff[tpY.Name]; !ok {
			return false
		}

		// check if target pool properties have changed
		tpX := diff[tpY.Name]
		if tpX.Port != tpY.Port || tpX.Protocol != tpY.Protocol ||
			tpX.PathPattern != tpY.PathPattern || tpX.StickySessions != tpY.StickySessions ||
			tpX.HealthCheckPort != tpY.HealthCheckPort {
			return false
		}

		// check if target IPs have changed
		if len(tpX.TargetIPs) != len(tpY.TargetIPs) {
			return false
		}

		diff2 := make(map[string]bool, len(tpX.TargetIPs))
		for _, ip := range tpX.TargetIPs {
			diff2[ip] = true
		}

		for _, ip := range tpY.TargetIPs {
			if _, ok := diff2[ip]; !ok {
				return false
			}

			delete(diff2, ip)
		}

		if len(diff2) != 0 {
			return false
		}

		delete(diff, tpY.Name)
	}

	if len(diff) == 0 {
		return true
	}

	return false
}
