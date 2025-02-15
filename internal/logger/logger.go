package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/yourusername/go-honeypot/internal/config"
)

// Logger defines the interface for logging operations
type Logger interface {
	Debug(msg string, fields ...interface{})
	Info(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
	Error(msg string, fields ...interface{})
	Fatal(msg string, fields ...interface{})
	With(fields ...interface{}) Logger
	Sync() error
}

// logger implements the Logger interface using zap
type logger struct {
	zap    *zap.SugaredLogger
	config config.LogConfig
}

var (
	instance Logger
	once     sync.Once
)

// New creates a new logger instance
func New(cfg config.LogConfig) (Logger, error) {
	var err error
	once.Do(func() {
		instance, err = newLogger(cfg)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create logger: %w", err)
	}
	return instance, nil
}

// newLogger creates and configures a new logger instance
func newLogger(cfg config.LogConfig) (Logger, error) {
	// Create log directory if it doesn't exist
	logDir := filepath.Dir(cfg.Path)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Configure log rotation
	rotator := &lumberjack.Logger{
		Filename:   cfg.Path,
		MaxSize:    cfg.MaxSize,    // megabytes
		MaxBackups: cfg.MaxBackups,
		MaxAge:     cfg.MaxAge,     // days
		Compress:   cfg.Compress,
	}

	// Parse log level
	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("invalid log level: %w", err)
	}

	// Create encoder config
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Create core
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(rotator),
		level,
	)

	// Create logger
	zapLogger := zap.New(core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
	)

	return &logger{
		zap:    zapLogger.Sugar(),
		config: cfg,
	}, nil
}

// Debug logs a debug message
func (l *logger) Debug(msg string, fields ...interface{}) {
	l.zap.Debugw(msg, fields...)
}

// Info logs an info message
func (l *logger) Info(msg string, fields ...interface{}) {
	l.zap.Infow(msg, fields...)
}

// Warn logs a warning message
func (l *logger) Warn(msg string, fields ...interface{}) {
	l.zap.Warnw(msg, fields...)
}

// Error logs an error message
func (l *logger) Error(msg string, fields ...interface{}) {
	l.zap.Errorw(msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *logger) Fatal(msg string, fields ...interface{}) {
	l.zap.Fatalw(msg, fields...)
}

// With creates a new logger with additional fields
func (l *logger) With(fields ...interface{}) Logger {
	return &logger{
		zap:    l.zap.With(fields...),
		config: l.config,
	}
}

// Sync flushes buffered logs
func (l *logger) Sync() error {
	return l.zap.Sync()
}

// AddContext adds context fields to a log message
func AddContext(fields ...interface{}) []interface{} {
	fields = append(fields,
		"timestamp", time.Now().Format(time.RFC3339),
		"pid", os.Getpid(),
	)
	return fields
}
