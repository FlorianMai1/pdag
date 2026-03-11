package metrics

import (
	"database/sql"

	"github.com/prometheus/client_golang/prometheus"
)

// DBPoolCollector exports sql.DBStats as Prometheus metrics on each scrape.
type DBPoolCollector struct {
	db *sql.DB

	openConns *prometheus.Desc
	idleConns *prometheus.Desc
	inUse     *prometheus.Desc
	waitCount *prometheus.Desc
}

// NewDBPoolCollector creates and registers a collector for the given *sql.DB.
func NewDBPoolCollector(db *sql.DB) *DBPoolCollector {
	c := &DBPoolCollector{
		db: db,
		openConns: prometheus.NewDesc("pdag_db_pool_open_connections",
			"Number of open connections to the database.", nil, nil),
		idleConns: prometheus.NewDesc("pdag_db_pool_idle_connections",
			"Number of idle connections in the pool.", nil, nil),
		inUse: prometheus.NewDesc("pdag_db_pool_in_use_connections",
			"Number of connections currently in use.", nil, nil),
		waitCount: prometheus.NewDesc("pdag_db_pool_wait_count_total",
			"Total number of connections waited for.", nil, nil),
	}
	prometheus.MustRegister(c)
	return c
}

func (c *DBPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.openConns
	ch <- c.idleConns
	ch <- c.inUse
	ch <- c.waitCount
}

func (c *DBPoolCollector) Collect(ch chan<- prometheus.Metric) {
	stats := c.db.Stats()
	ch <- prometheus.MustNewConstMetric(c.openConns, prometheus.GaugeValue, float64(stats.OpenConnections))
	ch <- prometheus.MustNewConstMetric(c.idleConns, prometheus.GaugeValue, float64(stats.Idle))
	ch <- prometheus.MustNewConstMetric(c.inUse, prometheus.GaugeValue, float64(stats.InUse))
	ch <- prometheus.MustNewConstMetric(c.waitCount, prometheus.CounterValue, float64(stats.WaitCount))
}
