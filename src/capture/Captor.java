package capture;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import jpcap.*;
import jpcap.packet.*;

import model.*;

public class Captor {

	private final long MAX_PACKETS = 10000;
	private NetworkInterface[] devices = JpcapCaptor.getDeviceList();
	private List<Packet> packets = new ArrayList<>();
	private JpcapCaptor jpcap = null;
	private boolean isLive;
	private Thread captureThread;
	private boolean isFilterEnabled = false;

	// 获取捕获的数据包
	public List<Packet> getPackets() {
		return packets;
	}

	// 显示网络设备列表
	public String[] showDevice() {
		if (devices == null) {
			return null;
		}
		String[] deviceNames = new String[devices.length];
		for (int i = 0; i < deviceNames.length; i++) {
			deviceNames[i] = devices[i].description == null ? devices[i].name : devices[i].description;
		}
		return deviceNames;
	}

	// 显示数据包的完整信息（十六进制和 ASCII 字符串格式）
	public String showPacket(Packet p) {
		byte[] bytes = new byte[p.header.length + p.data.length];
		System.arraycopy(p.header, 0, bytes, 0, p.header.length);
		System.arraycopy(p.data, 0, bytes, p.header.length, p.data.length);

		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < bytes.length; ) {
			for (int j = 0; j < 8 && i < bytes.length; j++, i++) {
				String hex = Integer.toHexString(bytes[i] & 0xff);
				sb.append((hex.length() == 1 ? "0" + hex : hex) + " ");
				if (bytes[i] < 32 || bytes[i] > 126)
					bytes[i] = 46;
			}
			sb.append("[").append(new String(bytes, i - 8, 8)).append("]\n");
		}
		return sb.toString();
	}

	// 设置捕获过滤器
	public void setFilter(String filter) {
		try {
			if ("http".equalsIgnoreCase(filter)) {
				isFilterEnabled = true;
			} else {
				jpcap.setFilter(filter, true);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 选择网卡设备
	public void chooseDevice(int index) {
		try {
			jpcap = JpcapCaptor.openDevice(devices[index], 1514, true, 50);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// 开始捕获数据包
	public void capturePackets() {
		if (jpcap != null) {
			isLive = true;
			startCaptureThread();
		}
	}

	private void startCaptureThread() {
		if (captureThread != null) return;

		captureThread = new Thread(() -> {
			while (captureThread != null) {
				if (jpcap.processPacket(1, handler) == 0 && !isLive) {
					stopCaptureThread();
				}
				Thread.yield();
			}
			jpcap.breakLoop();
		});
		captureThread.setPriority(Thread.MIN_PRIORITY);
		captureThread.start();
	}

	// 停止捕获线程
	public void stopCaptureThread() {
		captureThread = null;
	}

	// 数据包处理器
	private PacketReceiver handler = new PacketReceiver() {
		public void receivePacket(final Packet packet) {
			if (isFilterEnabled) {
				HTTP http = new HTTP();
				if (http.isBelong(packet)) {
					packets.add(packet);
				}
			} else {
				packets.add(packet);
			}
			if (packets.size() > MAX_PACKETS) {
				packets.remove(0);
			}
		}
	};
}
