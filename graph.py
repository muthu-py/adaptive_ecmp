import matplotlib.pyplot as plt

# Simulated RTT data
# RTT data with crossover at ~40s
time = [20, 30, 40, 50, 60, 70, 80, 90, 100]
rtt_traditional = [3.9, 4.3, 5.0, 6.4, 8.1, 9.6, 11.0, 12.5, 13.9]
rtt_adaptive = [4.2, 4.5, 4.7, 5.5, 6.3, 7.2, 8.0, 8.7, 9.3]

# Plotting
plt.figure(figsize=(10, 6))
plt.plot(time, rtt_traditional, color='cyan', label='Traditional ECMP', linewidth=2)
plt.plot(time, rtt_adaptive, color='white', label='Adaptive ECMP', linewidth=2)
plt.xlabel('Time (s)', fontsize=12, color="white" )
plt.ylabel('Average RTT (ms)', fontsize=12, color="white")
plt.title('Average RTT over Time: Adaptive vs Traditional ECMP', fontsize=14)
plt.grid(True)
plt.legend()
plt.gca().set_facecolor('black')
plt.gcf().patch.set_facecolor('black')
plt.xticks(color='red')
plt.yticks(color='red')
# plt.savefig('/mnt/data/adaptive_vs_traditional_rtt.png', dpi=300, bbox_inches='tight', facecolor='black')
plt.show()
