import sys
sys.path.insert(0, 'd:\\Elite_Coders\\AstraGuard-AI')

from core.component_health import SystemHealthMonitor, get_health_monitor
from state_machine.state_engine import StateMachine

print('=== Check Instance Identity ===')

# Simulate first test + teardown
monitor1 = SystemHealthMonitor()
print(f'Test 1 monitor id: {id(monitor1)}')
print(f'get_health_monitor() id: {id(get_health_monitor())}')
print(f'Are they the same: {monitor1 is get_health_monitor()}')

sm1 = StateMachine()
print(f'After StateMachine, monitor._components: {list(monitor1._components.keys())}')

# Simulate teardown
monitor1.reset()
print(f'After reset: _initialized={monitor1._initialized}')

# Simulate second test
print()
print('=== Second Test ===')
monitor2 = SystemHealthMonitor()
print(f'Test 2 monitor id: {id(monitor2)}')
print(f'monitor1 is monitor2: {monitor1 is monitor2}')
print(f'_initialized after second SystemHealthMonitor(): {monitor2._initialized}')
print(f'monitor2._components: {list(monitor2._components.keys())}')

print()
print('Creating StateMachine...')
sm2 = StateMachine()
print(f'After StateMachine: components={list(monitor2._components.keys())}')

print()
print('Getting health...')
health = monitor2.get_component_health('state_machine')
print(f'Health status: {health.status}')
