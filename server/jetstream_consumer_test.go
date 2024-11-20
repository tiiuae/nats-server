// Copyright 2022-2023 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_js_tests
// +build !skip_js_tests

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nuid"
	"github.com/tiiuae/nats.go"
)

func TestJetStreamConsumerMultipleFiltersRemoveFilters(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "consumer",
		FilterSubjects: []string{"one", "two"},
	})
	require_NoError(t, err)

	sendStreamMsg(t, nc, "one", "data")
	sendStreamMsg(t, nc, "two", "data")
	sendStreamMsg(t, nc, "three", "data")

	consumer, err := js.PullSubscribe("", "consumer", nats.Bind("TEST", "consumer"))
	require_NoError(t, err)

	msgs, err := consumer.Fetch(1)
	require_NoError(t, err)
	require_True(t, len(msgs) == 1)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "consumer",
		FilterSubjects: []string{},
	})
	require_NoError(t, err)

	msgs, err = consumer.Fetch(1)
	require_NoError(t, err)
	require_True(t, len(msgs) == 1)

	msgs, err = consumer.Fetch(1)
	require_NoError(t, err)
	require_True(t, len(msgs) == 1)
}

func TestJetStreamConsumerMultipleFiltersRace(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three", "four"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	var seqs []uint64
	var mu sync.Mutex

	total := 10_000
	var wg sync.WaitGroup

	send := func(subj string) {
		defer wg.Done()
		for i := 0; i < total; i++ {
			sendStreamMsg(t, nc, subj, "data")
		}
	}
	wg.Add(4)
	go send("one")
	go send("two")
	go send("three")
	go send("four")
	wg.Wait()

	mset.addConsumer(&ConsumerConfig{
		Durable:        "consumer",
		FilterSubjects: []string{"one", "two", "three"},
		AckPolicy:      AckExplicit,
	})

	done := make(chan struct{})
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func(t *testing.T) {
			defer wg.Done()

			c, err := js.PullSubscribe(_EMPTY_, "consumer", nats.Bind("TEST", "consumer"))
			require_NoError(t, err)

			for {
				select {
				case <-done:
					return
				default:
				}
				msgs, err := c.Fetch(10, nats.MaxWait(2*time.Second))
				// We don't want to stop before at expected number of messages, as we want
				// to also test against getting to many messages.
				// Because of that, we ignore timeout and connection closed errors.
				if err != nil && err != nats.ErrTimeout && err != nats.ErrConnectionClosed {
					t.Errorf("error while fetching messages: %v", err)
				}

				for _, msg := range msgs {
					info, err := msg.Metadata()
					require_NoError(t, err)
					mu.Lock()
					seqs = append(seqs, info.Sequence.Consumer)
					mu.Unlock()
					msg.Ack()
				}
			}
		}(t)
	}

	checkFor(t, 30*time.Second, 100*time.Millisecond, func() error {
		mu.Lock()
		defer mu.Unlock()
		if len(seqs) != 3*total {
			return fmt.Errorf("found %d messages instead of %d", len(seqs), 3*total)
		}
		slices.Sort(seqs)
		for i := 1; i < len(seqs); i++ {
			if seqs[i] != seqs[i-1]+1 {
				fmt.Printf("seqs: %+v\n", seqs)
				return fmt.Errorf("sequence mismatch at %v", i)
			}
		}
		return nil
	})
	close(done)
	wg.Wait()
}

func TestJetStreamConsumerMultipleConsumersSingleFilter(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	// Setup few subjects with varying messages count.
	subjects := []struct {
		subject  string
		messages int
		wc       bool
	}{
		{subject: "one", messages: 5000},
		{subject: "two", messages: 7500},
		{subject: "three", messages: 2500},
		{subject: "four", messages: 1000},
		{subject: "five.>", messages: 3000, wc: true},
	}

	totalMsgs := 0
	for _, subject := range subjects {
		totalMsgs += subject.messages
	}

	// Setup consumers, filtering some of the messages from the stream.
	consumers := []*struct {
		name         string
		subjects     []string
		expectedMsgs int
		delivered    atomic.Int32
	}{
		{name: "C1", subjects: []string{"one"}, expectedMsgs: 5000},
		{name: "C2", subjects: []string{"two"}, expectedMsgs: 7500},
		{name: "C3", subjects: []string{"one"}, expectedMsgs: 5000},
		{name: "C4", subjects: []string{"one"}, expectedMsgs: 5000},
	}

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three", "four", "five.>"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	for c, consumer := range consumers {
		_, err := mset.addConsumer(&ConsumerConfig{
			Durable:        consumer.name,
			FilterSubjects: consumer.subjects,
			AckPolicy:      AckExplicit,
			DeliverPolicy:  DeliverAll,
			AckWait:        time.Second * 30,
			DeliverSubject: nc.NewInbox(),
		})
		require_NoError(t, err)
		go func(c int, name string) {
			_, err = js.Subscribe("", func(m *nats.Msg) {
				require_NoError(t, m.Ack())
				require_NoError(t, err)
				consumers[c].delivered.Add(1)

			}, nats.Bind("TEST", name))
			require_NoError(t, err)
		}(c, consumer.name)
	}

	// Publish with random intervals, while consumers are active.
	var wg sync.WaitGroup
	for _, subject := range subjects {
		wg.Add(subject.messages)
		go func(subject string, messages int, wc bool) {
			nc, js := jsClientConnect(t, s)
			defer nc.Close()
			time.Sleep(time.Duration(rand.Int63n(1000)+1) * time.Millisecond)
			for i := 0; i < messages; i++ {
				time.Sleep(time.Duration(rand.Int63n(1000)+1) * time.Microsecond)
				// If subject has wildcard, add random last subject token.
				pubSubject := subject
				if wc {
					pubSubject = fmt.Sprintf("%v.%v", subject, rand.Int63n(10))
				}
				_, err := js.PublishAsync(pubSubject, []byte("data"))
				require_NoError(t, err)
				wg.Done()
			}
		}(subject.subject, subject.messages, subject.wc)
	}
	wg.Wait()

	checkFor(t, time.Second*10, time.Millisecond*500, func() error {
		for _, consumer := range consumers {
			info, err := js.ConsumerInfo("TEST", consumer.name)
			require_NoError(t, err)
			if info.Delivered.Consumer != uint64(consumer.expectedMsgs) {
				return fmt.Errorf("%v:expected consumer delivered seq %v, got %v. actually delivered: %v",
					consumer.name, consumer.expectedMsgs, info.Delivered.Consumer, consumer.delivered.Load())
			}
			if info.AckFloor.Consumer != uint64(consumer.expectedMsgs) {
				return fmt.Errorf("%v: expected consumer ack floor %v, got %v", consumer.name, totalMsgs, info.AckFloor.Consumer)
			}
			if consumer.delivered.Load() != int32(consumer.expectedMsgs) {

				return fmt.Errorf("%v: expected %v, got %v", consumer.name, consumer.expectedMsgs, consumer.delivered.Load())
			}
		}
		return nil
	})

}

func TestJetStreamConsumerMultipleConsumersMultipleFilters(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	// Setup few subjects with varying messages count.
	subjects := []struct {
		subject  string
		messages int
		wc       bool
	}{
		{subject: "one", messages: 50},
		{subject: "two", messages: 75},
		{subject: "three", messages: 250},
		{subject: "four", messages: 10},
		{subject: "five.>", messages: 300, wc: true},
	}

	totalMsgs := 0
	for _, subject := range subjects {
		totalMsgs += subject.messages
	}

	// Setup consumers, filtering some of the messages from the stream.
	consumers := []*struct {
		name         string
		subjects     []string
		expectedMsgs int
		delivered    atomic.Int32
	}{
		{name: "C1", subjects: []string{"one", "two"}, expectedMsgs: 125},
		{name: "C2", subjects: []string{"two", "three"}, expectedMsgs: 325},
		{name: "C3", subjects: []string{"one", "three"}, expectedMsgs: 300},
		{name: "C4", subjects: []string{"one", "five.>"}, expectedMsgs: 350},
	}

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three", "four", "five.>"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	for c, consumer := range consumers {
		_, err := mset.addConsumer(&ConsumerConfig{
			Durable:        consumer.name,
			FilterSubjects: consumer.subjects,
			AckPolicy:      AckExplicit,
			DeliverPolicy:  DeliverAll,
			AckWait:        time.Second * 30,
			DeliverSubject: nc.NewInbox(),
		})
		require_NoError(t, err)
		go func(c int, name string) {
			_, err = js.Subscribe("", func(m *nats.Msg) {
				require_NoError(t, m.Ack())
				require_NoError(t, err)
				consumers[c].delivered.Add(1)

			}, nats.Bind("TEST", name))
			require_NoError(t, err)
		}(c, consumer.name)
	}

	// Publish with random intervals, while consumers are active.
	var wg sync.WaitGroup
	for _, subject := range subjects {
		wg.Add(subject.messages)
		go func(subject string, messages int, wc bool) {
			nc, js := jsClientConnect(t, s)
			defer nc.Close()
			time.Sleep(time.Duration(rand.Int63n(1000)+1) * time.Millisecond)
			for i := 0; i < messages; i++ {
				time.Sleep(time.Duration(rand.Int63n(1000)+1) * time.Microsecond)
				// If subject has wildcard, add random last subject token.
				pubSubject := subject
				if wc {
					pubSubject = fmt.Sprintf("%v.%v", subject, rand.Int63n(10))
				}
				ack, err := js.PublishAsync(pubSubject, []byte("data"))
				require_NoError(t, err)
				go func() {
					ack.Ok()
					wg.Done()
				}()
			}
		}(subject.subject, subject.messages, subject.wc)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-time.After(time.Second * 15):
		t.Fatalf("Timed out waiting for acks")
	case <-done:
	}
	wg.Wait()

	checkFor(t, time.Second*15, time.Second*1, func() error {
		for _, consumer := range consumers {
			info, err := js.ConsumerInfo("TEST", consumer.name)
			require_NoError(t, err)
			if info.Delivered.Consumer != uint64(consumer.expectedMsgs) {
				return fmt.Errorf("%v:expected consumer delivered seq %v, got %v. actually delivered: %v",
					consumer.name, consumer.expectedMsgs, info.Delivered.Consumer, consumer.delivered.Load())
			}
			if info.AckFloor.Consumer != uint64(consumer.expectedMsgs) {
				return fmt.Errorf("%v: expected consumer ack floor %v, got %v", consumer.name, totalMsgs, info.AckFloor.Consumer)
			}
			if consumer.delivered.Load() != int32(consumer.expectedMsgs) {

				return fmt.Errorf("%v: expected %v, got %v", consumer.name, consumer.expectedMsgs, consumer.delivered.Load())
			}
		}
		return nil
	})

}

func TestJetStreamConsumerMultipleFiltersSequence(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three", "four", "five.>"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "DUR",
		FilterSubjects: []string{"one", "two"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
		DeliverSubject: nc.NewInbox(),
	})
	require_NoError(t, err)

	for i := 0; i < 20; i++ {
		sendStreamMsg(t, nc, "one", fmt.Sprintf("%d", i))
	}
	for i := 20; i < 40; i++ {
		sendStreamMsg(t, nc, "two", fmt.Sprintf("%d", i))
	}
	for i := 40; i < 60; i++ {
		sendStreamMsg(t, nc, "one", fmt.Sprintf("%d", i))
	}

	sub, err := js.SubscribeSync("", nats.Bind("TEST", "DUR"))
	require_NoError(t, err)

	for i := 0; i < 60; i++ {
		msg, err := sub.NextMsg(time.Second * 1)
		require_NoError(t, err)
		require_True(t, string(msg.Data) == fmt.Sprintf("%d", i))
	}
}

func TestJetStreamConsumerActions(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one", "two", "three", "four", "five.>"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	// Create Consumer. No consumers existed before, so should be fine.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "DUR",
		FilterSubjects: []string{"one", "two"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionCreate, false)
	require_NoError(t, err)
	// Create consumer again. Should be ok if action is CREATE but config is exactly the same.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "DUR",
		FilterSubjects: []string{"one", "two"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionCreate, false)
	require_NoError(t, err)
	// Create consumer again. Should error if action is CREATE.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "DUR",
		FilterSubjects: []string{"one"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionCreate, false)
	require_Error(t, err)

	// Update existing consumer. Should be fine, as consumer exists.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "DUR",
		FilterSubjects: []string{"one"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionUpdate, false)
	require_NoError(t, err)

	// Update consumer. Should error, as this consumer does not exist.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "NEW",
		FilterSubjects: []string{"one"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionUpdate, false)
	require_Error(t, err)

	// Create new ephemeral. Should be fine as the consumer doesn't exist already
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Name:           "EPH",
		FilterSubjects: []string{"one"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionCreate, false)
	require_NoError(t, err)

	// Trying to create it again right away. Should error as it already exists (and hasn't been cleaned up yet)
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Name:           "EPH",
		FilterSubjects: []string{"one"},
		AckPolicy:      AckExplicit,
		DeliverPolicy:  DeliverAll,
		AckWait:        time.Second * 30,
	}, ActionCreate, false)
	require_Error(t, err)
}

func TestJetStreamConsumerActionsOnWorkQueuePolicyStream(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: WorkQueuePolicy,
		Subjects:  []string{"one", "two", "three", "four", "five.>"},
	})
	require_NoError(t, err)

	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C1",
		FilterSubjects: []string{"one", "two"},
		AckPolicy:      AckExplicit,
	}, ActionCreate, false)
	require_NoError(t, err)

	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C2",
		FilterSubjects: []string{"three", "four"},
		AckPolicy:      AckExplicit,
	}, ActionCreate, false)
	require_NoError(t, err)

	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C3",
		FilterSubjects: []string{"five.*"},
		AckPolicy:      AckExplicit,
	}, ActionCreate, false)
	require_NoError(t, err)

	// Updating a consumer by removing a previous subject filter.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C1",
		FilterSubjects: []string{"one"}, // Remove a subject.
		AckPolicy:      AckExplicit,
	}, ActionUpdate, false)
	require_NoError(t, err)

	// Updating a consumer without overlapping subjects.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C2",
		FilterSubjects: []string{"three", "four", "two"}, // Add previously removed subject.
		AckPolicy:      AckExplicit,
	}, ActionUpdate, false)
	require_NoError(t, err)

	// Creating a consumer with overlapping subjects should return an error.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C4",
		FilterSubjects: []string{"one", "two", "three", "four"},
		AckPolicy:      AckExplicit,
	}, ActionCreate, false)
	require_Error(t, err)
	if !IsNatsErr(err, JSConsumerWQConsumerNotUniqueErr) {
		t.Errorf("want error %q, got %q", ApiErrors[JSConsumerWQConsumerNotUniqueErr], err)
	}

	// Updating a consumer with overlapping subjects should return an error.
	_, err = mset.addConsumerWithAction(&ConsumerConfig{
		Durable:        "C3",
		FilterSubjects: []string{"one", "two", "three", "four"},
		AckPolicy:      AckExplicit,
	}, ActionUpdate, false)
	require_Error(t, err)
	if !IsNatsErr(err, JSConsumerWQConsumerNotUniqueErr) {
		t.Errorf("want error %q, got %q", ApiErrors[JSConsumerWQConsumerNotUniqueErr], err)
	}
}

func TestJetStreamConsumerActionsViaAPI(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()
	acc := s.GlobalAccount()

	_, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Retention: LimitsPolicy,
		Subjects:  []string{"one"},
		MaxAge:    time.Second * 90,
	})
	require_NoError(t, err)

	// Update non-existing consumer, which should fail.
	request, err := json.Marshal(&CreateConsumerRequest{
		Action: ActionUpdate,
		Config: ConsumerConfig{
			Durable: "hello",
		},
		Stream: "TEST",
	})
	require_NoError(t, err)

	resp, err := nc.Request("$JS.API.CONSUMER.DURABLE.CREATE.TEST.hello", []byte(request), time.Second*6)
	require_NoError(t, err)
	var ccResp JSApiConsumerCreateResponse
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	require_Error(t, ccResp.Error)

	// create non existing consumer - which should be fine.
	ccResp.Error = nil
	request, err = json.Marshal(&CreateConsumerRequest{
		Action: ActionCreate,
		Config: ConsumerConfig{
			Durable: "hello",
		},
		Stream: "TEST",
	})
	require_NoError(t, err)

	resp, err = nc.Request("$JS.API.CONSUMER.DURABLE.CREATE.TEST.hello", []byte(request), time.Second*6)
	require_NoError(t, err)
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	if ccResp.Error != nil {
		t.Fatalf("expected nil, got %v", ccResp.Error)
	}

	// re-create existing consumer - which should be an error.
	ccResp.Error = nil
	request, err = json.Marshal(&CreateConsumerRequest{
		Action: ActionCreate,
		Config: ConsumerConfig{
			Durable:       "hello",
			FilterSubject: "one",
		},
		Stream: "TEST",
	})
	require_NoError(t, err)
	resp, err = nc.Request("$JS.API.CONSUMER.DURABLE.CREATE.TEST.hello", []byte(request), time.Second*6)
	require_NoError(t, err)
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	if ccResp.Error == nil {
		t.Fatalf("expected err, got nil")
	}

	// create a named ephemeral consumer
	ccResp.Error = nil
	request, err = json.Marshal(&CreateConsumerRequest{
		Action: ActionCreate,
		Config: ConsumerConfig{
			Name:          "ephemeral",
			FilterSubject: "one",
		},
		Stream: "TEST",
	})
	require_NoError(t, err)
	resp, err = nc.Request("$JS.API.CONSUMER.CREATE.TEST.ephemeral", []byte(request), time.Second*6)
	require_NoError(t, err)
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)

	// re-create existing consumer - which should be an error.
	ccResp.Error = nil
	request, err = json.Marshal(&CreateConsumerRequest{
		Action: ActionCreate,
		Config: ConsumerConfig{
			Name:          "ephemeral",
			FilterSubject: "one",
		},
		Stream: "TEST",
	})
	require_NoError(t, err)
	resp, err = nc.Request("$JS.API.CONSUMER.CREATE.TEST.ephemeral", []byte(request), time.Second*6)
	require_NoError(t, err)
	err = json.Unmarshal(resp.Data, &ccResp)
	require_NoError(t, err)
	if ccResp.Error == nil {
		t.Fatalf("expected err, got nil")
	}
}

func TestJetStreamConsumerActionsUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		given     []byte
		expected  ConsumerAction
		expectErr bool
	}{
		{name: "action create", given: []byte(`{"action": "create"}`), expected: ActionCreate},
		{name: "action update", given: []byte(`{"action": "update"}`), expected: ActionUpdate},
		{name: "no action", given: []byte("{}"), expected: ActionCreateOrUpdate},
		{name: "unknown", given: []byte(`{"action": "unknown"}`), expected: ActionCreateOrUpdate, expectErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			var request CreateConsumerRequest
			err := json.Unmarshal(test.given, &request)
			fmt.Printf("given: %v, expected: %v\n", test.expectErr, err)
			if !test.expectErr {
				require_NoError(t, err)
			} else {
				require_Error(t, err)
			}
			require_True(t, test.expected == request.Action)
		})
	}
}

func TestJetStreamConsumerMultipleFiltersLastPerSubject(t *testing.T) {
	c := createJetStreamClusterExplicit(t, "R3S", 3)
	defer c.shutdown()

	nc, js := jsClientConnect(t, c.randomServer())
	defer nc.Close()

	_, error := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"one", "two"},
		Replicas: 3,
	})
	require_NoError(t, error)

	sendStreamMsg(t, nc, "one", "1")
	sendStreamMsg(t, nc, "one", "2")
	sendStreamMsg(t, nc, "one", "3")
	sendStreamMsg(t, nc, "two", "1")
	sendStreamMsg(t, nc, "two", "2")
	sendStreamMsg(t, nc, "two", "3")

	_, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
		Name:           "C",
		FilterSubjects: []string{"one", "two"},
		DeliverPolicy:  nats.DeliverLastPerSubjectPolicy,
		Replicas:       3,
		DeliverSubject: "deliver",
	})
	require_NoError(t, err)

	consumer, err := js.SubscribeSync("", nats.Bind("TEST", "C"))
	require_NoError(t, err)

	// expect last message for subject "one"
	msg, err := consumer.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, "3", string(msg.Data))
	require_Equal(t, "one", msg.Subject)

	// expect last message for subject "two"
	msg, err = consumer.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, "3", string(msg.Data))
	require_Equal(t, "two", msg.Subject)

}

func consumerWithFilterSubjects(filterSubjects []string) *consumer {
	c := consumer{}
	for _, filter := range filterSubjects {
		sub := &subjectFilter{
			subject:          filter,
			hasWildcard:      subjectHasWildcard(filter),
			tokenizedSubject: tokenizeSubjectIntoSlice(nil, filter),
		}
		c.subjf = append(c.subjf, sub)
	}

	return &c
}

func filterSubjects(n int) []string {
	fs := make([]string, 0, n)
	for {
		literals := []string{"foo", "bar", nuid.Next(), "xyz", "abcdef"}
		fs = append(fs, strings.Join(literals, "."))
		if len(fs) == n {
			return fs
		}
		// Create more filterSubjects by going through the literals and replacing one with the '*' wildcard.
		l := len(literals)
		for i := 0; i < l; i++ {
			e := make([]string, l)
			for j := 0; j < l; j++ {
				if j == i {
					e[j] = "*"
				} else {
					e[j] = literals[j]
				}
			}
			fs = append(fs, strings.Join(e, "."))
			if len(fs) == n {
				return fs
			}
		}
	}
}

func TestJetStreamConsumerIsFilteredMatch(t *testing.T) {
	for _, test := range []struct {
		name           string
		filterSubjects []string
		subject        string
		result         bool
	}{
		{"no filter", []string{}, "foo.bar", true},
		{"literal match", []string{"foo.baz", "foo.bar"}, "foo.bar", true},
		{"literal mismatch", []string{"foo.baz", "foo.bar"}, "foo.ban", false},
		{"wildcard > match", []string{"bar.>", "foo.>"}, "foo.bar", true},
		{"wildcard > match", []string{"bar.>", "foo.>"}, "bar.foo", true},
		{"wildcard > mismatch", []string{"bar.>", "foo.>"}, "baz.foo", false},
		{"wildcard * match", []string{"bar.*", "foo.*"}, "foo.bar", true},
		{"wildcard * match", []string{"bar.*", "foo.*"}, "bar.foo", true},
		{"wildcard * mismatch", []string{"bar.*", "foo.*"}, "baz.foo", false},
		{"wildcard * match", []string{"foo.*.x", "foo.*.y"}, "foo.bar.x", true},
		{"wildcard * match", []string{"foo.*.x", "foo.*.y", "foo.*.z"}, "foo.bar.z", true},
		{"many mismatch", filterSubjects(100), "foo.bar.do.not.match.any.filter.subject", false},
		{"many match", filterSubjects(100), "foo.bar.12345.xyz.abcdef", true}, // will be matched by "foo.bar.*.xyz.abcdef"
	} {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := consumerWithFilterSubjects(test.filterSubjects)
			if res := c.isFilteredMatch(test.subject); res != test.result {
				t.Fatalf("Subject %q filtered match of %v, should be %v, got %v",
					test.subject, test.filterSubjects, test.result, res)
			}
		})
	}
}

func TestJetStreamConsumerWorkQueuePolicyOverlap(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo.*.*"},
		Retention: nats.WorkQueuePolicy,
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "ConsumerA",
		FilterSubject: "foo.bar.*",
		AckPolicy:     nats.AckExplicitPolicy,
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable:       "ConsumerB",
		FilterSubject: "foo.*.bar",
		AckPolicy:     nats.AckExplicitPolicy,
	})
	require_Error(t, err)
	require_True(t, strings.Contains(err.Error(), "unique"))
}

func TestJetStreamConsumerIsEqualOrSubsetMatch(t *testing.T) {
	for _, test := range []struct {
		name           string
		filterSubjects []string
		subject        string
		result         bool
	}{
		{"no filter", []string{}, "foo.bar", false},
		{"literal match", []string{"foo.baz", "foo.bar"}, "foo.bar", true},
		{"literal mismatch", []string{"foo.baz", "foo.bar"}, "foo.ban", false},
		{"literal match", []string{"bar.>", "foo.>"}, "foo.>", true},
		{"subset match", []string{"bar.foo.>", "foo.bar.>"}, "bar.>", true},
		{"subset mismatch", []string{"bar.>", "foo.>"}, "baz.foo.>", false},
		{"literal match", filterSubjects(100), "foo.bar.*.xyz.abcdef", true},
		{"subset match", filterSubjects(100), "foo.bar.>", true},
	} {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			c := consumerWithFilterSubjects(test.filterSubjects)
			if res := c.isEqualOrSubsetMatch(test.subject); res != test.result {
				t.Fatalf("Subject %q subset match of %v, should be %v, got %v",
					test.subject, test.filterSubjects, test.result, res)
			}
		})
	}
}

func TestJetStreamConsumerBackOff(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	for _, test := range []struct {
		name      string
		config    nats.ConsumerConfig
		shouldErr bool
	}{
		{
			name: "backoff_with_max_deliver",
			config: nats.ConsumerConfig{
				MaxDeliver: 3,
				BackOff:    []time.Duration{time.Second, time.Minute},
			},
			shouldErr: false,
		},
		{
			name: "backoff_with_max_deliver_smaller",
			config: nats.ConsumerConfig{
				MaxDeliver: 2,
				BackOff:    []time.Duration{time.Second, time.Minute, time.Hour},
			},
			shouldErr: true,
		},
		{
			name: "backoff_with_default_max_deliver",
			config: nats.ConsumerConfig{
				BackOff: []time.Duration{time.Second, time.Minute, time.Hour},
			},
			shouldErr: false,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := js.AddStream(&nats.StreamConfig{
				Name:     test.name,
				Subjects: []string{test.name},
			})
			require_NoError(t, err)

			_, err = js.AddConsumer(test.name, &test.config)
			require_True(t, test.shouldErr == (err != nil))
			if test.shouldErr {
				require_True(t, strings.Contains(err.Error(), "max deliver"))
			}

			// test if updating consumers works too.
			test.config.Durable = "consumer"
			_, err = js.AddConsumer(test.name, &nats.ConsumerConfig{
				Durable: test.config.Durable,
			})
			require_NoError(t, err)

			test.config.Description = "Updated"
			_, err = js.UpdateConsumer(test.name, &test.config)
			require_True(t, test.shouldErr == (err != nil))
			if test.shouldErr {
				require_True(t, strings.Contains(err.Error(), "max deliver"))
			}
		})

	}
}

func TestJetStreamConsumerDelete(t *testing.T) {
	tests := []struct {
		name     string
		replicas int
	}{
		{"single server", 1},
		{"clustered", 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var s *Server
			if test.replicas == 1 {
				s = RunBasicJetStreamServer(t)
				defer s.Shutdown()
			} else {
				c := createJetStreamClusterExplicit(t, "R3S", test.replicas)
				defer c.shutdown()
				s = c.randomServer()
			}

			nc, js := jsClientConnect(t, s)
			defer nc.Close()

			_, err := js.AddStream(&nats.StreamConfig{
				Name:     "TEST",
				Subjects: []string{"events.>"},
				MaxAge:   time.Second * 90,
				Replicas: test.replicas,
			})
			require_NoError(t, err)

			_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
				Durable:       "consumer",
				FilterSubject: "events.>",
				Replicas:      test.replicas,
			})
			require_NoError(t, err)

			js.Publish("events.1", []byte("hello"))

			cr := JSApiConsumerGetNextRequest{
				Batch:   10,
				Expires: time.Second * 30,
			}
			crBytes, err := json.Marshal(cr)
			require_NoError(t, err)

			inbox := nats.NewInbox()
			consumerSub, err := nc.SubscribeSync(inbox)
			require_NoError(t, err)

			err = nc.PublishRequest(fmt.Sprintf(JSApiRequestNextT, "TEST", "consumer"), inbox, crBytes)
			require_NoError(t, err)

			msg, err := consumerSub.NextMsg(time.Second * 30)
			require_NoError(t, err)
			require_Equal(t, "hello", string(msg.Data))

			js.DeleteConsumer("TEST", "consumer")

			msg, err = consumerSub.NextMsg(time.Second * 30)
			require_NoError(t, err)

			if !strings.Contains(string(msg.Header.Get("Description")), "Consumer Deleted") {
				t.Fatalf("Expected exclusive consumer error, got %q", msg.Header.Get("Description"))
			}
		})

	}
}

func TestJetStreamConsumerFetchWithDrain(t *testing.T) {
	t.Skip()

	test := func(t *testing.T, cc *nats.ConsumerConfig) {
		s := RunBasicJetStreamServer(t)
		defer s.Shutdown()

		nc, js := jsClientConnect(t, s)
		defer nc.Close()

		_, err := js.AddStream(&nats.StreamConfig{
			Name:      "TEST",
			Subjects:  []string{"foo"},
			Retention: nats.LimitsPolicy,
		})
		require_NoError(t, err)

		_, err = js.AddConsumer("TEST", cc)
		require_NoError(t, err)

		const messages = 10_000

		for i := 0; i < messages; i++ {
			sendStreamMsg(t, nc, "foo", fmt.Sprintf("%d", i+1))
		}

		cr := JSApiConsumerGetNextRequest{
			Batch:   100_000,
			Expires: 10 * time.Second,
		}
		crBytes, err := json.Marshal(cr)
		require_NoError(t, err)

		msgs := make(map[int]int)

		processMsg := func(t *testing.T, sub *nats.Subscription, msgs map[int]int) bool {
			msg, err := sub.NextMsg(time.Second)
			if err != nil {
				return false
			}
			metadata, err := msg.Metadata()
			require_NoError(t, err)
			require_NoError(t, msg.Ack())

			v, err := strconv.Atoi(string(msg.Data))
			require_NoError(t, err)
			require_Equal(t, uint64(v), metadata.Sequence.Stream)

			if _, ok := msgs[int(metadata.Sequence.Stream-1)]; !ok && len(msgs) > 0 {
				t.Logf("Stream Sequence gap detected: current %d", metadata.Sequence.Stream)
			}
			if _, ok := msgs[int(metadata.Sequence.Stream)]; ok {
				t.Fatalf("Message for seq %d has been seen before", metadata.Sequence.Stream)
			}
			// We do not expect official redeliveries here so this should always be 1.
			if metadata.NumDelivered != 1 {
				t.Errorf("Expected NumDelivered of 1, got %d for seq %d",
					metadata.NumDelivered, metadata.Sequence.Stream)
			}
			msgs[int(metadata.Sequence.Stream)] = int(metadata.NumDelivered)
			return true
		}

		for {
			inbox := nats.NewInbox()
			sub, err := nc.SubscribeSync(inbox)
			require_NoError(t, err)

			err = nc.PublishRequest(fmt.Sprintf(JSApiRequestNextT, "TEST", "C"), inbox, crBytes)
			require_NoError(t, err)

			// Drain after first message processed.
			processMsg(t, sub, msgs)
			sub.Drain()

			for {
				if !processMsg(t, sub, msgs) {
					if len(msgs) == messages {
						return
					}
					break
				}
			}
		}
	}

	t.Run("no-backoff", func(t *testing.T) {
		test(t, &nats.ConsumerConfig{
			Durable:   "C",
			AckPolicy: nats.AckExplicitPolicy,
			AckWait:   20 * time.Second,
		})
	})
	t.Run("with-backoff", func(t *testing.T) {
		test(t, &nats.ConsumerConfig{
			Durable:   "C",
			AckPolicy: nats.AckExplicitPolicy,
			AckWait:   20 * time.Second,
			BackOff:   []time.Duration{25 * time.Millisecond, 100 * time.Millisecond, 250 * time.Millisecond},
		})
	})
}

func TestJetStreamConsumerLongSubjectHang(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	readSubj := "a1."
	purgeSubj := "a2."
	_, err := js.AddStream(&nats.StreamConfig{
		Name:        "TEST",
		Subjects:    []string{readSubj + ">", purgeSubj + ">"},
		AllowRollup: true,
	})
	require_NoError(t, err)

	prefix := strings.Repeat("a", 22)
	for i := 0; i < 2; i++ {
		subj := readSubj + prefix + fmt.Sprintf("%d", i)
		_, err = js.Publish(subj, []byte("hello"))
		require_NoError(t, err)
		chunkSubj := purgeSubj + fmt.Sprintf("%d", i)
		_, err = js.Publish(chunkSubj, []byte("contents"))
		require_NoError(t, err)
	}
	err = js.PurgeStream("TEST", &nats.StreamPurgeRequest{Subject: purgeSubj + ">"})
	require_NoError(t, err)

	si, err := js.StreamInfo("TEST")
	require_NoError(t, err)
	// we should have 2 msgs left after purge
	require_Equal(t, si.State.Msgs, 2)

	sub, err := js.SubscribeSync(readSubj+">", nats.OrderedConsumer(), nats.DeliverLastPerSubject())
	require_NoError(t, err)
	defer sub.Unsubscribe()

	for i := 0; i < 2; i++ {
		m, err := sub.NextMsg(500 * time.Millisecond)
		require_NoError(t, err)
		require_True(t, string(m.Data) == "hello")
	}
}

func TestJetStreamConsumerPedanticMode(t *testing.T) {

	singleServerTemplate := `
			listen: 127.0.0.1:-1
			jetstream: {
				max_mem_store: 2MB,
				max_file_store: 8MB,
				store_dir: '%s',
				limits: {max_request_batch: 250}
			}
			no_auth_user: u
			accounts {
				ONE {
					users = [ { user: "u", pass: "s3cr3t!" } ]
					jetstream: enabled
				}
				$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
			}`

	clusterTemplate := `
			listen: 127.0.0.1:-1
			server_name: %s
			jetstream: {
				max_mem_store: 2MB,
				max_file_store: 8MB,
				store_dir: '%s',
				limits: {max_request_batch: 250}
			}
			cluster {
				name: %s
				listen: 127.0.0.1:%d
				routes = [%s]
			}
			no_auth_user: u
			accounts {
				ONE {
					users = [ { user: "u", pass: "s3cr3t!" } ]
					jetstream: enabled
				}
				$SYS { users = [ { user: "admin", pass: "s3cr3t!" } ] }
			}`

	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	tests := []struct {
		name                  string
		givenConfig           ConsumerConfig
		givenLimits           nats.StreamConsumerLimits
		serverTemplateSingle  string
		serverTemplateCluster string
		shouldError           bool
		pedantic              bool
		replicas              int
	}{
		{
			name: "default_non_pedantic",
			givenConfig: ConsumerConfig{
				Durable: "durable",
			},
			givenLimits: nats.StreamConsumerLimits{
				InactiveThreshold: time.Minute,
				MaxAckPending:     100,
			},
			shouldError: false,
			pedantic:    false,
		},
		{
			name: "default_pedantic_inactive_threshold",
			givenConfig: ConsumerConfig{
				Durable: "durable",
			},
			givenLimits: nats.StreamConsumerLimits{
				InactiveThreshold: time.Minute,
			},
			shouldError: true,
			pedantic:    true,
		},
		{
			name: "default_pedantic_max_ack_pending",
			givenConfig: ConsumerConfig{
				Durable: "durable",
			},
			givenLimits: nats.StreamConsumerLimits{
				MaxAckPending: 100,
			},
			shouldError: true,
			pedantic:    true,
		},
		{
			name: "pedantic_backoff_no_ack_wait",
			givenConfig: ConsumerConfig{
				Durable: "durable",
				BackOff: []time.Duration{time.Second, time.Minute},
			},
			pedantic:    true,
			shouldError: true,
		},
		{
			name: "backoff_no_ack_wait",
			givenConfig: ConsumerConfig{
				Durable: "durable",
				BackOff: []time.Duration{time.Second, time.Minute},
			},
			pedantic:    false,
			shouldError: false,
		},
		{
			name: "max_batch_requests",
			givenConfig: ConsumerConfig{
				Durable: "durable",
			},
			serverTemplateSingle:  singleServerTemplate,
			serverTemplateCluster: clusterTemplate,
			pedantic:              false,
			shouldError:           false,
		},
		{
			name: "pedantic_max_batch_requests",
			givenConfig: ConsumerConfig{
				Durable: "durable",
			},
			serverTemplateSingle:  singleServerTemplate,
			serverTemplateCluster: clusterTemplate,
			pedantic:              true,
			shouldError:           true,
		},
	}

	for _, test := range tests {
		for _, mode := range []string{"clustered", "single"} {
			t.Run(fmt.Sprintf("%v_%v", mode, test.name), func(t *testing.T) {

				var s *Server
				if mode == "single" {
					s = RunBasicJetStreamServer(t)
					defer s.Shutdown()
				} else {
					c := createJetStreamClusterExplicit(t, "R3S", 3)
					defer c.shutdown()
					s = c.randomServer()
				}

				replicas := 1
				if mode == "clustered" {
					replicas = 3
				}

				nc, js := jsClientConnect(t, s)
				defer nc.Close()

				js.AddStream(&nats.StreamConfig{
					Name:     test.name,
					Subjects: []string{"foo"},
					Replicas: replicas,
					ConsumerLimits: nats.StreamConsumerLimits{
						InactiveThreshold: time.Minute,
						MaxAckPending:     100,
					},
				})

				_, err := addConsumerWithError(t, nc, &CreateConsumerRequest{
					Stream:   test.name,
					Config:   test.givenConfig,
					Action:   ActionCreateOrUpdate,
					Pedantic: test.pedantic,
				})
				require_True(t, (err != nil) == test.shouldError)
				if err != nil {
					require_True(t, strings.Contains(err.Error(), "pedantic"))
				}
			})
		}
	}
}

func TestJetStreamConsumerStuckAckPending(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	type ActiveWorkItem struct {
		ID     int
		Expiry time.Time
	}

	_, err := js.AddStream(&nats.StreamConfig{
		Name:              "TEST_ACTIVE_WORK_ITEMS",
		Discard:           nats.DiscardOld,
		MaxMsgsPerSubject: 1,
		Subjects:          []string{"TEST_ACTIVE_WORK_ITEMS.>"},
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST_ACTIVE_WORK_ITEMS", &nats.ConsumerConfig{
		Durable:       "testactiveworkitemsconsumer",
		AckPolicy:     nats.AckExplicitPolicy,
		MaxAckPending: -1,
		MaxWaiting:    20000,
		AckWait:       15 * time.Second,
	})
	require_NoError(t, err)

	sub, err := js.PullSubscribe("TEST_ACTIVE_WORK_ITEMS.>", "testactiveworkitemsconsumer", nats.BindStream("TEST_ACTIVE_WORK_ITEMS"))
	require_NoError(t, err)

	errs := make(chan error)
	go func() {
		for {
			msgs, err := sub.Fetch(200)
			if err != nil {
				// test is done. stop the loop.
				if errors.Is(err, nats.ErrSubscriptionClosed) || errors.Is(err, nats.ErrConnectionClosed) {
					return
				}
				if !errors.Is(err, nats.ErrTimeout) {
					errs <- err
					return
				}
				continue
			}
			for _, msg := range msgs {
				msg := msg
				var workItem ActiveWorkItem
				if err := json.Unmarshal(msg.Data, &workItem); err != nil {
					errs <- err
					return
				}

				now := time.Now()
				// If the work item has not expired, nak it with the respective delay.
				if workItem.Expiry.After(now) {
					msg.NakWithDelay(workItem.Expiry.Sub(now))
				} else {
					msg.Ack()
				}
			}
		}
	}()

	for i := 0; i < 25_000; i++ {
		// Publish item to TEST_ACTIVE_WORK_ITEMS stream with an expiry time.
		workItem := ActiveWorkItem{ID: i, Expiry: time.Now().Add(30 * time.Second)}
		data, err := json.Marshal(workItem)
		require_NoError(t, err)

		_, err = js.Publish(fmt.Sprintf("TEST_ACTIVE_WORK_ITEMS.%d", i), data)
		require_NoError(t, err)

		// Update expiry time and republish item to TEST_ACTIVE_WORK_ITEMS stream.
		workItem.Expiry = time.Now().Add(3 * time.Second)
		data, err = json.Marshal(workItem)
		require_NoError(t, err)
		_, err = js.Publish(fmt.Sprintf("TEST_ACTIVE_WORK_ITEMS.%d", i), data)
		require_NoError(t, err)
	}
	noChange := false
	lastNumAckPending := 0
	checkFor(t, 60*time.Second, 3*time.Second, func() error {
		select {
		case err := <-errs:
			t.Fatalf("consumer goroutine failed: %v", err)
		default:
		}
		ci, err := js.ConsumerInfo("TEST_ACTIVE_WORK_ITEMS", "testactiveworkitemsconsumer")
		require_NoError(t, err)

		if lastNumAckPending != 0 && lastNumAckPending == ci.NumAckPending {
			noChange = true
		}
		lastNumAckPending = ci.NumAckPending

		// If we have no change since last check, we can fail the test before `totalWait` timeout.
		if ci.NumAckPending > 0 && ci.NumPending == 0 {
			if noChange {
				_, err := sub.Fetch(1)
				if err != nil && errors.Is(err, nats.ErrTimeout) {

					t.Fatalf("num ack pending: %d\t num pending: %v\n", ci.NumAckPending, ci.NumPending)
				}
			}
			return fmt.Errorf("num ack pending: %d\t num pending: %v\n", ci.NumAckPending, ci.NumPending)
		}
		return nil
	})
}

func TestJetStreamConsumerPinned(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo.>", "bar", "baz"},
		Retention: LimitsPolicy,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "C",
		FilterSubject:  "foo.>",
		PriorityGroups: []string{"A"},
		PriorityPolicy: PriorityPinnedClient,
		AckPolicy:      AckExplicit,
		PinnedTTL:      10 * time.Second,
	})
	require_NoError(t, err)

	for i := 0; i < 100; i++ {
		msg := nats.NewMsg(fmt.Sprintf("foo.%d", i))
		msg.Data = []byte(fmt.Sprintf("msg-%d", i))
		// Add headers to check if we properly serialize Nats-Pin-Id with and without headers.
		if i%2 == 0 {
			msg.Header.Add("Some-Header", "Value")
		}
		js.PublishMsg(msg)
	}

	req := JSApiConsumerGetNextRequest{Batch: 3, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}
	reqb, _ := json.Marshal(req)
	reply := "ONE"
	replies, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqb)
	require_NoError(t, err)

	reply2 := "TWO"
	replies2, err := nc.SubscribeSync(reply2)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply2, reqb)
	require_NoError(t, err)

	// This is the first Pull Request, so it should become the pinned one.
	msg, err := replies.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, msg)
	// Check if we are really pinned.
	pinned := msg.Header.Get("Nats-Pin-Id")
	if pinned == "" {
		t.Fatalf("Expected pinned message, got none")
	}

	// Here, we should have pull request that just idles, as it is not pinned.
	_, err = replies2.NextMsg(time.Second)
	require_Error(t, err)

	// While the pinned one continues to get messages.
	msg, err = replies.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, msg)

	// Just making sure that the other one does not get round-robined message.
	_, err = replies2.NextMsg(time.Second)
	require_Error(t, err)

	// Now let's send a request with wrong pinned id.
	req = JSApiConsumerGetNextRequest{Batch: 3, Expires: 250 * time.Millisecond, PriorityGroup: PriorityGroup{
		Id:    "WRONG",
		Group: "A",
	}}
	reqBad, err := json.Marshal(req)
	require_NoError(t, err)
	replies3, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqBad)
	require_NoError(t, err)

	// and make sure we got error telling us it's wrong ID.
	msg, err = replies3.NextMsg(time.Second)
	require_NoError(t, err)
	if msg.Header.Get("Status") != "423" {
		t.Fatalf("Expected 423, got %v", msg.Header.Get("Status"))
	}
	// Send a new request with a good pinned ID.
	req = JSApiConsumerGetNextRequest{Batch: 3, Expires: 250 * time.Millisecond, PriorityGroup: PriorityGroup{
		Id:    pinned,
		Group: "A",
	}}
	reqb, _ = json.Marshal(req)
	reply = "FOUR"
	replies4, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqb)
	require_NoError(t, err)

	// and check that we got a message.
	msg, err = replies4.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, msg)

	advisories, err := nc.SubscribeSync("$JS.EVENT.ADVISORY.CONSUMER.*.TEST.C")
	require_NoError(t, err)

	// Send a new request without pin ID, which should work after the TTL.
	req = JSApiConsumerGetNextRequest{Batch: 3, Expires: 50 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}
	reqb, _ = json.Marshal(req)
	reply = "FIVE"
	replies5, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqb)

	checkFor(t, 20*time.Second, 1*time.Second, func() error {
		_, err = replies5.NextMsg(500 * time.Millisecond)
		if err == nil {
			return nil
		}
		return err
	})

	advisory, err := advisories.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, fmt.Sprintf("%s.TEST.C", JSAdvisoryConsumerUnpinnedPre), advisory.Subject)
	advisory, err = advisories.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, fmt.Sprintf("%s.TEST.C", JSAdvisoryConsumerPinnedPre), advisory.Subject)

	// Manually unpin the current fetch request.
	request := JSApiConsumerUnpinRequest{Group: "A"}
	requestData, err := json.Marshal(request)
	require_NoError(t, err)
	msg, err = nc.Request("$JS.API.CONSUMER.UNPIN.TEST.C", requestData, time.Second*1)
	require_NoError(t, err)

	var response JSApiConsumerUnpinResponse
	err = json.Unmarshal(msg.Data, &response)
	require_NoError(t, err)
	require_True(t, response.Error == nil)

	// check if we got proper advisories.
	advisory, err = advisories.NextMsg(time.Second)
	require_NoError(t, err)
	require_Equal(t, fmt.Sprintf("%s.TEST.C", JSAdvisoryConsumerUnpinnedPre), advisory.Subject)

	replies6, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqBad)
	require_NoError(t, err)

	_, err = replies6.NextMsg(time.Second * 5)
	require_NoError(t, err)
}

// This tests if Unpin works correctly when there are no pending messages.
// It checks if the next pinned client will be different than the first one
// after new messages is published.
func TestJetStreamConsumerUnpinNoMessages(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo"},
		Retention: LimitsPolicy,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "C",
		FilterSubject:  "foo",
		PriorityGroups: []string{"A"},
		PriorityPolicy: PriorityPinnedClient,
		AckPolicy:      AckExplicit,
		PinnedTTL:      30 * time.Second,
	})
	require_NoError(t, err)

	req := JSApiConsumerGetNextRequest{Batch: 30, Expires: 60 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}
	reqb, _ := json.Marshal(req)
	reply := "ONE"
	replies, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqb)
	require_NoError(t, err)

	reply2 := "TWO"
	replies2, err := nc.SubscribeSync(reply2)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply2, reqb)
	require_NoError(t, err)

	sendStreamMsg(t, nc, "foo", "data")
	sendStreamMsg(t, nc, "foo", "data")

	msg, err := replies.NextMsg(1 * time.Second)
	pinId := msg.Header.Get("Nats-Pin-Id")
	require_NotEqual(t, pinId, "")
	require_NoError(t, err)
	_, err = replies.NextMsg(1 * time.Second)
	require_NoError(t, err)

	_, err = replies2.NextMsg(1 * time.Second)
	require_Error(t, err)

	unpinRequest := func(t *testing.T, nc *nats.Conn, stream, consumer, group string) *ApiError {
		var response JSApiConsumerUnpinResponse
		request := JSApiConsumerUnpinRequest{Group: group}
		requestData, err := json.Marshal(request)
		require_NoError(t, err)
		msg, err := nc.Request(fmt.Sprintf("$JS.API.CONSUMER.UNPIN.%s.%s", stream, consumer), requestData, time.Second*1)
		require_NoError(t, err)
		err = json.Unmarshal(msg.Data, &response)
		require_NoError(t, err)
		return response.Error
	}

	unpinError := unpinRequest(t, nc, "TEST", "C", "A")
	require_True(t, unpinError == nil)

	sendStreamMsg(t, nc, "foo", "data")
	sendStreamMsg(t, nc, "foo", "data")

	// Old pinned client should get info that it is no longer pinned.
	msg, err = replies.NextMsg(1 * time.Second)
	require_NoError(t, err)
	require_Equal(t, msg.Header.Get("Status"), "423")

	// While the new one should get the message and new pin.
	msg, err = replies2.NextMsg(1 * time.Second)
	require_NoError(t, err)
	require_Equal(t, string(msg.Data), "data")
	require_NotEqual(t, msg.Header.Get("Nats-Pin-Id"), pinId)
}

// In some scenarios, if the next waiting request is the same as the old pinned, it could be picked as a new pin.
// This test replicates that behavior and checks if the new pin is different than the old one.
func TestJetStreamConsumerUnpinPickDifferentRequest(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo"},
		Retention: LimitsPolicy,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "C",
		FilterSubject:  "foo",
		PriorityGroups: []string{"A"},
		PriorityPolicy: PriorityPinnedClient,
		AckPolicy:      AckExplicit,
		PinnedTTL:      30 * time.Second,
	})
	require_NoError(t, err)

	sendStreamMsg(t, nc, "foo", "data")

	req := JSApiConsumerGetNextRequest{Batch: 5, Expires: 15 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}

	reqBytes, err := json.Marshal(req)
	require_NoError(t, err)

	firstInbox := "FIRST"
	firstReplies, err := nc.SubscribeSync(firstInbox)
	require_NoError(t, err)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", firstInbox, reqBytes)

	msg, err := firstReplies.NextMsg(1 * time.Second)
	require_NoError(t, err)
	pinId := msg.Header.Get("Nats-Pin-Id")
	require_NotEqual(t, pinId, "")

	reqPinned := JSApiConsumerGetNextRequest{Batch: 5, Expires: 15 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
		Id:    pinId,
	}}
	_, err = json.Marshal(reqPinned)
	require_NoError(t, err)

	secondInbox := "SECOND"
	secondReplies, err := nc.SubscribeSync(secondInbox)
	require_NoError(t, err)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", secondInbox, reqBytes)

	_, err = secondReplies.NextMsg(1 * time.Second)
	require_Error(t, err)

	unpinRequest := func(t *testing.T, nc *nats.Conn, stream, consumer, group string) *ApiError {
		var response JSApiConsumerUnpinResponse
		request := JSApiConsumerUnpinRequest{Group: group}
		requestData, err := json.Marshal(request)
		require_NoError(t, err)
		msg, err := nc.Request(fmt.Sprintf("$JS.API.CONSUMER.UNPIN.%s.%s", stream, consumer), requestData, time.Second*1)
		require_NoError(t, err)
		err = json.Unmarshal(msg.Data, &response)
		require_NoError(t, err)
		return response.Error
	}

	unpinRequest(t, nc, "TEST", "C", "A")
	_, err = firstReplies.NextMsg(1 * time.Second)
	// If there are no messages in the stream, do not expect unpin message to arrive.
	// Advisory will be sent immediately, but messages with headers - only when there is anything to be sent.
	require_Error(t, err)
	// Send a new message to the stream.
	sendStreamMsg(t, nc, "foo", "data")
	// Check if the old pinned will get the information about bad pin.
	msg, err = firstReplies.NextMsg(1 * time.Second)
	require_NoError(t, err)
	require_Equal(t, msg.Header.Get("Status"), "423")
	// Make sure that the old pin is cleared.
	require_Equal(t, msg.Header.Get("Nats-Pin-Id"), "")

	// Try different wr.
	msg, err = secondReplies.NextMsg(1 * time.Second)
	require_NoError(t, err)
	// Make sure that its pin is different than the old one and not empty.
	require_NotEqual(t, msg.Header.Get("Nats-Pin-Id"), pinId)
	require_NotEqual(t, msg.Header.Get("Nats-Pin-Id"), "")
}

func TestJetStreamPinnedTTL(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo"},
		Retention: LimitsPolicy,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "C",
		FilterSubject:  "foo",
		PriorityGroups: []string{"A"},
		PriorityPolicy: PriorityPinnedClient,
		AckPolicy:      AckExplicit,
		PinnedTTL:      3 * time.Second,
	})
	require_NoError(t, err)

	for i := 0; i < 10; i++ {
		sendStreamMsg(t, nc, "foo", "data")
	}

	req := JSApiConsumerGetNextRequest{Batch: 1, Expires: 10 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}

	reqBytes, err := json.Marshal(req)
	require_NoError(t, err)

	firstInbox := "FIRST"
	firstReplies, err := nc.SubscribeSync(firstInbox)
	require_NoError(t, err)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", firstInbox, reqBytes)

	msg, err := firstReplies.NextMsg(1 * time.Second)
	require_NoError(t, err)
	pinId := msg.Header.Get("Nats-Pin-Id")
	require_NotEqual(t, pinId, "")

	secondInbox := "SECOND"
	secondReplies, err := nc.SubscribeSync(secondInbox)
	require_NoError(t, err)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", secondInbox, reqBytes)

	// Expect error, as first request should be still pinned.
	_, err = secondReplies.NextMsg(1 * time.Second)
	require_Error(t, err)

	// During the 5 second window, the first Pin should time out and this request
	// should become the pinned one and get the message.
	msg, err = secondReplies.NextMsg(5 * time.Second)
	require_NoError(t, err)
	newPinId := msg.Header.Get("Nats-Pin-Id")
	require_NotEqual(t, newPinId, pinId)
	require_NotEqual(t, newPinId, "")

	thirdInbox := "THIRD"
	thirdReplies, err := nc.SubscribeSync(thirdInbox)
	require_NoError(t, err)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", thirdInbox, reqBytes)

	// The same process as above, but tests different codepath - one where Pin
	// is set on existing waiting request.
	msg, err = thirdReplies.NextMsg(5 * time.Second)
	require_NoError(t, err)
	require_NotEqual(t, msg.Header.Get("Nats-Pin-Id"), pinId)
	require_NotEqual(t, msg.Header.Get("Nats-Pin-Id"), newPinId)
	require_NotEqual(t, newPinId, "")

}

func TestJetStreamConsumerUnpin(t *testing.T) {
	single := RunBasicJetStreamServer(t)
	defer single.Shutdown()
	nc, js := jsClientConnect(t, single)
	defer nc.Close()

	cluster := createJetStreamClusterExplicit(t, "R3S", 3)
	defer cluster.shutdown()
	cnc, cjs := jsClientConnect(t, cluster.randomServer())
	defer cnc.Close()

	// Create a stream and consumer for both single server and clustered mode.
	for _, server := range []struct {
		replicas int
		js       nats.JetStreamContext
		nc       *nats.Conn
	}{
		{1, js, nc},
		{3, cjs, cnc},
	} {

		_, err := server.js.AddStream(&nats.StreamConfig{
			Name:     "TEST",
			Subjects: []string{"foo.>", "bar", "baz"},
			Replicas: server.replicas,
		})
		require_NoError(t, err)

		consumerConfig := CreateConsumerRequest{
			Stream: "TEST",
			Action: ActionCreate,
			Config: ConsumerConfig{
				Durable:        "C",
				FilterSubject:  "foo.>",
				PriorityGroups: []string{"A"},
				PriorityPolicy: PriorityPinnedClient,
				AckPolicy:      AckExplicit,
				PinnedTTL:      10 * time.Second,
			},
		}
		req, err := json.Marshal(consumerConfig)
		require_NoError(t, err)
		rmsg, err := server.nc.Request(fmt.Sprintf(JSApiDurableCreateT, consumerConfig.Stream, consumerConfig.Config.Durable), req, 5*time.Second)
		require_NoError(t, err)

		var resp JSApiConsumerCreateResponse
		err = json.Unmarshal(rmsg.Data, &resp)
		require_NoError(t, err)
		require_True(t, resp.Error == nil)

	}
	cluster.waitOnStreamLeader("$G", "TEST")
	cluster.waitOnConsumerLeader("$G", "TEST", "C")

	unpinRequest := func(t *testing.T, nc *nats.Conn, stream, consumer, group string) *ApiError {
		var response JSApiConsumerUnpinResponse
		request := JSApiConsumerUnpinRequest{Group: group}
		requestData, err := json.Marshal(request)
		require_NoError(t, err)
		msg, err := nc.Request(fmt.Sprintf("$JS.API.CONSUMER.UNPIN.%s.%s", stream, consumer), requestData, time.Second*1)
		require_NoError(t, err)
		err = json.Unmarshal(msg.Data, &response)
		require_NoError(t, err)
		return response.Error
	}

	for _, test := range []struct {
		name     string
		nc       *nats.Conn
		stream   string
		consumer string
		group    string
		err      *ApiError
	}{
		{"unpin non-existing group", nc, "TEST", "C", "B", &ApiError{ErrCode: uint16(JSConsumerInvalidPriorityGroupErr)}},
		{"unpin on missing stream", nc, "NOT_EXIST", "C", "A", &ApiError{ErrCode: uint16(JSStreamNotFoundErr)}},
		{"unpin on missing consumer", nc, "TEST", "NOT_EXIST", "A", &ApiError{ErrCode: uint16(JSConsumerNotFoundErr)}},
		{"unpin missing group", nc, "TEST", "C", "", &ApiError{ErrCode: uint16(JSInvalidJSONErr)}},
		{"unpin bad group name", nc, "TEST", "C", "group    name\r\n", &ApiError{ErrCode: uint16(JSConsumerInvalidGroupNameErr)}},
		{"ok unpin", nc, "TEST", "C", "A", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := unpinRequest(t, nc, test.stream, test.consumer, test.group)
			if test.err != nil {
				require_True(t, err.ErrCode == test.err.ErrCode)
			} else {
				require_True(t, err == nil)
			}
		})
		t.Run(fmt.Sprintf("%s clustered", test.name), func(t *testing.T) {
			err := unpinRequest(t, cnc, test.stream, test.consumer, test.group)
			if test.err != nil {
				require_True(t, err.ErrCode == test.err.ErrCode)
			} else {
				require_True(t, err == nil)
			}
		})
	}
}

func TestJetStreamConsumerWithPriorityGroups(t *testing.T) {
	single := RunBasicJetStreamServer(t)
	defer single.Shutdown()
	nc, js := jsClientConnect(t, single)
	defer nc.Close()

	cluster := createJetStreamClusterExplicit(t, "R3S", 3)
	defer cluster.shutdown()
	cnc, cjs := jsClientConnect(t, cluster.randomServer())
	defer cnc.Close()

	// Create a stream and consumer for both single server and clustered mode.
	for _, server := range []struct {
		replicas int
		js       nats.JetStreamContext
	}{
		{1, js},
		{3, cjs},
	} {

		_, err := server.js.AddStream(&nats.StreamConfig{
			Name:     "TEST",
			Subjects: []string{"foo.>", "bar", "baz"},
			Replicas: server.replicas,
		})
		require_NoError(t, err)
	}
	cluster.waitOnStreamLeader("$G", "TEST")

	for _, test := range []struct {
		name     string
		nc       *nats.Conn
		stream   string
		consumer string
		groups   []string
		mode     PriorityPolicy
		err      *ApiError
	}{
		{"Pinned Consumer with Priority Group", nc, "TEST", "PINNED", []string{"A"}, PriorityPinnedClient, nil},
		{"Pinned Consumer with Priority Group, clustered", cnc, "TEST", "PINNED", []string{"A"}, PriorityPinnedClient, nil},
		{"Overflow Consumer with Priority Group", nc, "TEST", "OVERFLOW", []string{"A"}, PriorityOverflow, nil},
		{"Overflow Consumer with Priority Group, clustered", cnc, "TEST", "OVERFLOW", []string{"A"}, PriorityOverflow, nil},
		{"Pinned Consumer without Priority Group", nc, "TEST", "PINNED_NO_GROUP", nil, PriorityPinnedClient, &ApiError{ErrCode: uint16(JSConsumerPriorityPolicyWithoutGroup)}},
		{"Pinned Consumer without Priority Group, clustered", cnc, "TEST", "PINNED_NO_GROUP", nil, PriorityPinnedClient, &ApiError{ErrCode: uint16(JSConsumerPriorityPolicyWithoutGroup)}},
		{"Overflow Consumer without Priority Group", nc, "TEST", "PINNED_NO_GROUP", nil, PriorityOverflow, &ApiError{ErrCode: uint16(JSConsumerPriorityPolicyWithoutGroup)}},
		{"Overflow Consumer without Priority Group, clustered", cnc, "TEST", "PINNED_NO_GROUP", nil, PriorityOverflow, &ApiError{ErrCode: uint16(JSConsumerPriorityPolicyWithoutGroup)}},
		{"Pinned Consumer with empty Priority Group", nc, "TEST", "PINNED_NO_GROUP", []string{""}, PriorityPinnedClient, &ApiError{ErrCode: uint16(JSConsumerEmptyGroupName)}},
		{"Pinned Consumer with empty Priority Group, clustered", cnc, "TEST", "PINNED_NO_GROUP", []string{""}, PriorityPinnedClient, &ApiError{ErrCode: uint16(JSConsumerEmptyGroupName)}},
		{"Pinned Consumer with empty Priority Group", nc, "TEST", "PINNED_NO_GROUP", []string{""}, PriorityOverflow, &ApiError{ErrCode: uint16(JSConsumerEmptyGroupName)}},
		{"Pinned Consumer with empty Priority Group, clustered", cnc, "TEST", "PINNED_NO_GROUP", []string{""}, PriorityOverflow, &ApiError{ErrCode: uint16(JSConsumerEmptyGroupName)}},
	} {
		t.Run(test.name, func(t *testing.T) {

			consumerConfig := CreateConsumerRequest{
				Stream: "TEST",
				Action: ActionCreate,
				Config: ConsumerConfig{
					Durable:        test.consumer,
					FilterSubject:  "foo.>",
					PriorityGroups: test.groups,
					PriorityPolicy: test.mode,
					AckPolicy:      AckExplicit,
					PinnedTTL:      10 * time.Second,
				},
			}
			req, err := json.Marshal(consumerConfig)
			require_NoError(t, err)
			rmsg, err := test.nc.Request(fmt.Sprintf(JSApiDurableCreateT, consumerConfig.Stream, consumerConfig.Config.Durable), req, 5*time.Second)
			require_NoError(t, err)

			var resp JSApiConsumerCreateResponse
			err = json.Unmarshal(rmsg.Data, &resp)
			require_NoError(t, err)

			if test.err != nil {
				require_True(t, resp.Error.ErrCode == test.err.ErrCode)
			} else {
				require_True(t, resp.Error == nil)
			}
		})
	}
}

func TestJetStreamConsumerPriorityPullRequests(t *testing.T) {
	single := RunBasicJetStreamServer(t)
	defer single.Shutdown()
	nc, js := jsClientConnect(t, single)
	defer nc.Close()

	cluster := createJetStreamClusterExplicit(t, "R3S", 3)
	defer cluster.shutdown()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"pinned.>", "overflow.>"},
	})
	require_NoError(t, err)

	_, err = js.AddConsumer("TEST", &nats.ConsumerConfig{
		Durable: "STANDARD",
	})
	require_NoError(t, err)

	consumerConfig := CreateConsumerRequest{
		Stream: "TEST",
		Action: ActionCreate,
		Config: ConsumerConfig{
			Durable:        "PINNED",
			FilterSubject:  "pinned.>",
			PriorityGroups: []string{"A"},
			PriorityPolicy: PriorityPinnedClient,
			AckPolicy:      AckExplicit,
			PinnedTTL:      10 * time.Second,
		},
	}
	req, err := json.Marshal(consumerConfig)
	require_NoError(t, err)
	rmsg, err := nc.Request(fmt.Sprintf(JSApiDurableCreateT, consumerConfig.Stream, consumerConfig.Config.Durable), req, 5*time.Second)
	require_NoError(t, err)

	var resp JSApiConsumerCreateResponse
	err = json.Unmarshal(rmsg.Data, &resp)
	require_NoError(t, err)
	require_True(t, resp.Error == nil)

	consumerConfig = CreateConsumerRequest{
		Stream: "TEST",
		Action: ActionCreate,
		Config: ConsumerConfig{
			Durable:        "OVERFLOW",
			FilterSubject:  "overflow.>",
			PriorityGroups: []string{"A"},
			PriorityPolicy: PriorityOverflow,
			AckPolicy:      AckExplicit,
			PinnedTTL:      5 * time.Second,
		},
	}
	req, err = json.Marshal(consumerConfig)
	require_NoError(t, err)
	rmsg, err = nc.Request(fmt.Sprintf(JSApiDurableCreateT, consumerConfig.Stream, consumerConfig.Config.Durable), req, 5*time.Second)
	require_NoError(t, err)

	err = json.Unmarshal(rmsg.Data, &resp)
	require_NoError(t, err)
	require_True(t, resp.Error == nil)

	for i := 0; i < 50; i++ {
		sendStreamMsg(t, nc, "pinned.1", fmt.Sprintf("msg-%d", i))
		sendStreamMsg(t, nc, "overflow.1", fmt.Sprintf("msg-%d", i))
	}

	for _, test := range []struct {
		name        string
		nc          *nats.Conn
		consumer    string
		request     JSApiConsumerGetNextRequest
		description string
	}{
		{"Pinned Pull Request", nc, "PINNED", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A"}}, ""},
		{"Pinned Pull Request, no group", nc, "PINNED", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{}}, "Bad Request - Priority Group missing"},
		{"Pinned Pull Request, bad group", nc, "PINNED", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "Bad"}}, "Bad Request - Invalid Priority Group"},
		{"Pinned Pull Request, against Overflow", nc, "OVERFLOW", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", Id: "PINNED-ID"}}, "Bad Request - Not a Pinned Client Priority consumer"},
		{"Pinned Pull Request, against standard consumer", nc, "STANDARD", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", Id: "PINNED-ID"}}, "Bad Request - Not a Pinned Client Priority consumer"},
		{"Overflow Pull Request, overflow below threshold", nc, "OVERFLOW", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", MinPending: 1000}}, "Request Timeout"},
		{"Overflow Pull Request, overflow above threshold", nc, "OVERFLOW", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", MinPending: 10}}, ""},
		{"Overflow Pull Request, against pinned", nc, "PINNED", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", MinPending: 10}}, "Bad Request - Not a Overflow Priority consumer"},
		{"Overflow Pull Request, against standard consumer", nc, "STANDARD", JSApiConsumerGetNextRequest{Batch: 1, Expires: 5 * time.Second, PriorityGroup: PriorityGroup{Group: "A", MinPending: 10}}, "Bad Request - Not a Overflow Priority consumer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbox := nats.NewInbox()
			replies, err := test.nc.SubscribeSync(inbox)
			reqb, _ := json.Marshal(test.request)
			require_NoError(t, err)
			nc.PublishRequest(fmt.Sprintf("$JS.API.CONSUMER.MSG.NEXT.TEST.%s", test.consumer), inbox, reqb)
			require_NoError(t, err)
			msg, err := replies.NextMsg(10 * time.Second)
			require_NoError(t, err)
			require_Equal(t, test.description, msg.Header.Get("Description"))
		})
	}
}

func TestJetStreamConsumerOverflow(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, _ := jsClientConnect(t, s)
	defer nc.Close()

	acc := s.GlobalAccount()

	mset, err := acc.addStream(&StreamConfig{
		Name:      "TEST",
		Subjects:  []string{"foo.>", "bar", "baz"},
		Retention: LimitsPolicy,
		Storage:   FileStorage,
	})
	require_NoError(t, err)

	_, err = mset.addConsumer(&ConsumerConfig{
		Durable:        "C",
		FilterSubject:  "foo.>",
		PriorityGroups: []string{"A"},
		PriorityPolicy: PriorityOverflow,
		AckPolicy:      AckExplicit,
	})
	require_NoError(t, err)

	sendStreamMsg(t, nc, "foo.1", "msg-1")

	// nothing unacked, so should return nothing.
	req := JSApiConsumerGetNextRequest{Batch: 1, Expires: 90 * time.Second, PriorityGroup: PriorityGroup{
		MinAckPending: 1,
		Group:         "A",
	}}
	ackPending1 := sendRequest(t, nc, "ackPending", req)
	_, err = ackPending1.NextMsg(time.Second)
	require_Error(t, err)

	// one pending message, so should return it.
	req = JSApiConsumerGetNextRequest{Batch: 1, Expires: 90 * time.Second, PriorityGroup: PriorityGroup{
		MinPending: 1,
		Group:      "A",
	}}
	numPending1 := sendRequest(t, nc, "singleOverflow", req)
	msg, err := numPending1.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, msg)

	sendStreamMsg(t, nc, "foo.1", "msg-2")
	sendStreamMsg(t, nc, "foo.1", "msg-3")

	// overflow set to 10, so we should not get any messages, as there are only few pending.
	req = JSApiConsumerGetNextRequest{Batch: 1, Expires: 90 * time.Second, PriorityGroup: PriorityGroup{
		MinPending: 10,
		Group:      "A",
	}}
	numPending10 := sendRequest(t, nc, "overflow", req)
	_, err = numPending10.NextMsg(time.Second)
	require_Error(t, err)

	// without overflow, we should get messages.
	req = JSApiConsumerGetNextRequest{Batch: 1, Expires: 90 * time.Second}
	fetchNoOverflow := sendRequest(t, nc, "without_overflow", req)
	noOverflowMsg, err := fetchNoOverflow.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, noOverflowMsg)

	// Now add more messages.
	for i := 0; i < 100; i++ {
		sendStreamMsg(t, nc, "foo.1", "msg-1")
	}

	// and previous batch should receive messages now.
	msg, err = numPending10.NextMsg(time.Second * 5)
	require_NoError(t, err)
	require_NotNil(t, msg)

	// But one with max ack pending should get nothing.
	req = JSApiConsumerGetNextRequest{Batch: 1, Expires: 90 * time.Second, PriorityGroup: PriorityGroup{
		MinAckPending: 50,
		Group:         "A",
	}}
	maxAckPending50 := sendRequest(t, nc, "maxAckPending", req)
	_, err = maxAckPending50.NextMsg(time.Second)
	require_Error(t, err)

	// However, when we miss a lot of acks, we should get messages on overflow with max ack pending.
	req = JSApiConsumerGetNextRequest{Batch: 200, Expires: 90 * time.Second, PriorityGroup: PriorityGroup{
		Group: "A",
	}}
	fetchNoOverflow = sendRequest(t, nc, "without_overflow", req)
	noOverflowMsg, err = fetchNoOverflow.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, noOverflowMsg)

	msg, err = maxAckPending50.NextMsg(time.Second)
	require_NoError(t, err)
	require_NotNil(t, msg)
}

func TestJetStreamConsumerMultipleFitersWithStartDate(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	past := time.Now().Add(-90 * time.Second)

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"events.>"},
	})
	require_NoError(t, err)

	sendStreamMsg(t, nc, "events.foo", "msg-1")
	sendStreamMsg(t, nc, "events.bar", "msg-2")
	sendStreamMsg(t, nc, "events.baz", "msg-3")
	sendStreamMsg(t, nc, "events.biz", "msg-4")
	sendStreamMsg(t, nc, "events.faz", "msg-5")
	sendStreamMsg(t, nc, "events.foo", "msg-6")
	sendStreamMsg(t, nc, "events.biz", "msg-7")

	for _, test := range []struct {
		name                   string
		filterSubjects         []string
		startTime              time.Time
		expectedMessages       uint64
		expectedStreamSequence uint64
	}{
		{"Single-Filter-first-sequence", []string{"events.foo"}, past, 2, 0},
		{"Multiple-Filter-first-sequence", []string{"events.foo", "events.bar", "events.baz"}, past, 4, 0},
		{"Multiple-Filters-second-subject", []string{"events.bar", "events.baz"}, past, 2, 1},
		{"Multiple-Filters-first-last-subject", []string{"events.foo", "events.biz"}, past, 4, 0},
		{"Multiple-Filters-in-future", []string{"events.foo", "events.biz"}, time.Now().Add(1 * time.Minute), 0, 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			info, err := js.AddConsumer("TEST", &nats.ConsumerConfig{
				Durable:        test.name,
				FilterSubjects: test.filterSubjects,
				DeliverPolicy:  nats.DeliverByStartTimePolicy,
				OptStartTime:   &test.startTime,
			})
			require_NoError(t, err)
			require_Equal(t, test.expectedStreamSequence, info.Delivered.Stream)
			require_Equal(t, test.expectedMessages, info.NumPending)
		})
	}

}

func TestPriorityGroupNameRegex(t *testing.T) {
	for _, test := range []struct {
		name  string
		group string
		valid bool
	}{
		{"valid-short", "A", true},
		{"valid-with-accepted-special-chars", "group/consumer=A", true},
		{"empty", "", false},
		{"with-space", "A B", false},
		{"with-tab", "A   B", false},
		{"too-long-name", "group-name-that-is-too-long", false},
		{"line-termination", "\r\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			require_Equal(t, test.valid, validGroupName.MatchString(test.group))
		})
	}
}

func sendRequest(t *testing.T, nc *nats.Conn, reply string, req JSApiConsumerGetNextRequest) *nats.Subscription {
	reqb, _ := json.Marshal(req)
	replies, err := nc.SubscribeSync(reply)
	nc.PublishRequest("$JS.API.CONSUMER.MSG.NEXT.TEST.C", reply, reqb)
	require_NoError(t, err)
	return replies
}

func Benchmark____JetStreamConsumerIsFilteredMatch(b *testing.B) {
	subject := "foo.bar.do.not.match.any.filter.subject"
	for n := 1; n <= 1024; n *= 2 {
		name := fmt.Sprintf("%d filter subjects", int(n))
		c := consumerWithFilterSubjects(filterSubjects(int(n)))
		b.Run(name, func(b *testing.B) {
			c.isFilteredMatch(subject)
		})
	}
}

// https://github.com/nats-io/nats-server/issues/6085
func TestJetStreamConsumerBackoffNotRespectedWithMultipleInflightRedeliveries(t *testing.T) {
	s := RunBasicJetStreamServer(t)
	defer s.Shutdown()

	nc, js := jsClientConnect(t, s)
	defer nc.Close()

	_, err := js.AddStream(&nats.StreamConfig{
		Name:     "TEST",
		Subjects: []string{"events.>"},
	})
	require_NoError(t, err)

	maxDeliver := 3
	backoff := []time.Duration{2 * time.Second, 4 * time.Second}
	sub, err := js.SubscribeSync(
		"events.>",
		nats.MaxDeliver(maxDeliver),
		nats.BackOff(backoff),
		nats.AckExplicit(),
	)
	require_NoError(t, err)

	calculateExpectedBackoff := func(numDelivered int) time.Duration {
		expectedBackoff := 500 * time.Millisecond
		for i := 0; i < numDelivered-1 && i < len(backoff); i++ {
			expectedBackoff += backoff[i]
		}
		return expectedBackoff
	}

	// We get one message to be redelivered using the final backoff duration.
	firstMsgSent := time.Now()
	sendStreamMsg(t, nc, "events.first", "msg-1")
	_, err = sub.NextMsg(time.Second)
	require_NoError(t, err)
	require_LessThan(t, time.Since(firstMsgSent), calculateExpectedBackoff(1))
	_, err = sub.NextMsg(5 * time.Second)
	require_NoError(t, err)
	require_LessThan(t, time.Since(firstMsgSent), calculateExpectedBackoff(2))
	// This message will be redelivered with the final/highest backoff below.

	// If we now send a new message, the pending timer should be reset to the first backoff.
	// Otherwise, if it remains at the final backoff duration we'll get this message redelivered too late.
	sendStreamMsg(t, nc, "events.second", "msg-2")

	for {
		msg, err := sub.NextMsg(5 * time.Second)
		require_NoError(t, err)
		if msg.Subject == "events.first" {
			require_LessThan(t, time.Since(firstMsgSent), calculateExpectedBackoff(3))
			continue
		}

		// We expect the second message to be redelivered using the specified backoff strategy.
		// Before, the first redelivery of the second message would be sent after the highest backoff duration.
		metadata, err := msg.Metadata()
		require_NoError(t, err)
		numDelivered := int(metadata.NumDelivered)
		expectedBackoff := calculateExpectedBackoff(numDelivered)
		require_LessThan(t, time.Since(metadata.Timestamp), expectedBackoff)

		// We've received all message, test passed.
		if numDelivered >= maxDeliver {
			break
		}
	}
}
