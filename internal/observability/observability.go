package observability

import (
	"errors"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

const MetricsPath = "/__system__/__metrics__"

type Monitor struct {
	registry *prometheus.Registry
	requests *prometheus.CounterVec
	latency  *prometheus.HistogramVec
}

func New() *Monitor {
	m := &Monitor{
		registry: prometheus.NewRegistry(),
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "proxy_requests_total", Help: "Requests completed through response headers."}, []string{"method", "status"}),
		latency:  prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "proxy_request_duration_seconds", Help: "Request processing through response headers; streamed body transfer is excluded.", Buckets: []float64{0.001, 0.01, 0.1, 0.3, 1.2, 5, 10}}, []string{"method"}),
	}
	m.registry.MustRegister(m.requests, m.latency, prometheus.NewGoCollector(), prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	return m
}

func (m *Monitor) Handler(c fiber.Ctx) error {
	start := time.Now()
	err := c.Next()
	status := c.Response().StatusCode()
	if err != nil {
		status = fiber.StatusInternalServerError
		var ferr *fiber.Error
		if errors.As(err, &ferr) {
			status = ferr.Code
		}
	}
	method := string(c.Request().Header.Method())
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
	default:
		method = "OTHER"
	}
	m.requests.WithLabelValues(method, strconv.Itoa(status)).Inc()
	m.latency.WithLabelValues(method).Observe(time.Since(start).Seconds())
	return err
}

func (m *Monitor) Mount(app *fiber.App) {
	handler := fasthttpadaptor.NewFastHTTPHandler(promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{}))
	app.Get(MetricsPath, func(c fiber.Ctx) error { handler(c.RequestCtx()); return nil })
}
