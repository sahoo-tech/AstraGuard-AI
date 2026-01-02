from core.component_health import SystemHealthMonitor

print('Creating monitor #1')
m1 = SystemHealthMonitor()
print(f'  m1._initialized = {m1._initialized}')
print(f'  m1._components = {m1._components}')

print()
print('Resetting monitor')
m1.reset()
print(f'  m1._initialized = {m1._initialized}')

print()
print('Creating monitor #2 (same instance)')
m2 = SystemHealthMonitor()
print(f'  m2 is m1: {m2 is m1}')
print(f'  m2._initialized = {m2._initialized}')
print(f'  m2._components = {m2._components}')
