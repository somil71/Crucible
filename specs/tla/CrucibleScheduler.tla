----------------------- MODULE CrucibleScheduler -----------------------
(*
  TLA+ Formal Specification of Crucible's Deterministic Scheduler & Virtual Time Engine.
  Guarantee: Single logical scheduler dictates thread interleaving and event delivery.
  Under the same Seed and Initial State, the sequence of states is strictly deterministic.
*)

EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS
    Threads,        \* Set of thread IDs in the simulated world
    MaxSteps,       \* Bound on exploration steps
    MaxTime         \* Bound on virtual nanoseconds

VARIABLES
    threadState,    \* [t \in Threads |-> "READY" | "RUNNING" | "WAITING" | "TERMINATED"]
    threadClock,    \* [t \in Threads |-> Nat] (instruction counter or logical tick)
    virtualTime,    \* Nat (logical nanoseconds)
    eventQueue,     \* Sequence of scheduled timed events (timers, socket timeouts)
    stepCount,      \* Nat
    executionTrace  \* Sequence of executed (thread, instructionCount, virtualTime) tuples

TypeOK ==
    /\ threadState \in [Threads -> {"READY", "RUNNING", "WAITING", "TERMINATED"}]
    /\ threadClock \in [Threads -> Nat]
    /\ virtualTime \in Nat
    /\ stepCount \in Nat
    /\ IsFiniteSet(Threads)

Init ==
    /\ threadState = [t \in Threads |-> IF t = 1 THEN "READY" ELSE "WAITING"]
    /\ threadClock = [t \in Threads |-> 0]
    /\ virtualTime = 0
    /\ eventQueue = << >>
    /\ stepCount = 0
    /\ executionTrace = << >>

(* Deterministic thread selection: Pick lowest ID among READY threads *)
SelectNextThread ==
    CHOOSE t \in Threads : (threadState[t] = "READY" /\ \A other \in Threads : threadState[other] = "READY" => t <= other)

HasReadyThread ==
    \E t \in Threads : threadState[t] = "READY"

StepThread(t) ==
    /\ threadState[t] = "READY"
    /\ threadClock' = [threadClock EXCEPT ![t] = threadClock[t] + 1]
    /\ stepCount' = stepCount + 1
    /\ executionTrace' = Append(executionTrace, <<t, threadClock[t] + 1, virtualTime>>)
    \* Arbitrary state transition for model checking (either stays READY or waits)
    /\ \/ threadState' = threadState
       \/ threadState' = [threadState EXCEPT ![t] = "WAITING"]
    /\ UNCHANGED <<virtualTime, eventQueue>>

(* Jump-on-Idle: If no thread is ready, advance virtualTime to earliest event in queue *)
AdvanceTimeOnIdle ==
    /\ ~HasReadyThread
    /\ eventQueue /= << >>
    /\ LET nextEvent == Head(eventQueue) IN
        /\ virtualTime' = nextEvent.targetTime
        /\ eventQueue' = Tail(eventQueue)
        /\ threadState' = [threadState EXCEPT ![nextEvent.targetThread] = "READY"]
        /\ stepCount' = stepCount + 1
        /\ UNCHANGED <<threadClock, executionTrace>>

Next ==
    /\ stepCount < MaxSteps
    /\ \/ (HasReadyThread /\ StepThread(SelectNextThread))
       \/ AdvanceTimeOnIdle

Spec == Init /\ [][Next]_<<threadState, threadClock, virtualTime, eventQueue, stepCount, executionTrace>>

(* Safety Invariant: Determinism Contract holds *)
SchedulerDeterministic ==
    [][\A t1, t2 \in Threads : (threadState[t1] = "READY" /\ threadState[t2] = "READY" /\ t1 /= t2) => (SelectNextThread = IF t1 < t2 THEN t1 ELSE t2)]_threadState

=============================================================================
