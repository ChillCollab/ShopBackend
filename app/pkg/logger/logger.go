package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"runtime"

	"github.com/sirupsen/logrus"
)

type writerHook struct {
	Writer    []io.Writer
	LogLevels []logrus.Level
}

func (hook *writerHook) Fire(e *logrus.Entry) error {
	line, err := e.String()
	if err != nil {
		return err
	}
	for _, w := range hook.Writer {
		w.Write([]byte(line))
	}
	return err
}

func (hook *writerHook) Levels() []logrus.Level {
	return hook.LogLevels
}

var e *logrus.Entry

type Logger struct {
	*logrus.Entry
}

func GetLogger() Logger {
	return Logger{e}
}

func (l *Logger) GetLoggerWithField(k string, v interface{}) *logrus.Entry {
	return l.WithField(k, v)
}

func init() {
	l := logrus.New()
	l.SetReportCaller(true)
	l.Formatter = &logrus.TextFormatter{
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			filename := path.Base(frame.File)
			return fmt.Sprintf("%s()", frame.Function), fmt.Sprintf("%s:%d", filename, frame.Line)
		},
		DisableColors: false,
		FullTimestamp: false,
	}
	err := os.Mkdir("logs", 0777)
	if err != nil {
		fmt.Print(err.Error())
	}
	file, err := os.OpenFile("logs/errors.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Default().Printf("Failed to open error log file: %v", err)
		return
	}
	l.SetOutput(io.Discard)

	l.AddHook(&writerHook{
		Writer:    []io.Writer{file, os.Stdout},
		LogLevels: logrus.AllLevels,
	})

	l.SetLevel(logrus.TraceLevel)

	e = logrus.NewEntry(l)
}
