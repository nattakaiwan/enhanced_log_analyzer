# enhanced_log_analyzer

🌟 ฟีเจอร์หลัก:
1. Web Interface ที่สวยงาม

Dashboard แบบ Interactive
การจัดกลุ่มข้อมูลเป็น Tabs
Custom CSS สำหรับการแสดงผล
Responsive design

2. การอัปโหลดไฟล์

รองรับไฟล์ .log, .txt, .csv
มีข้อมูลตัวอย่างสำหรับทดสอบ
Progress bar ขณะประมวลผล
การจัดการข้อผิดพลาด

3. กราฟแบบ Interactive (Plotly)

Line charts สำหรับ trends
Bar charts สำหรับการเปรียบเทียบ
Pie charts สำหรับการแจกแจง
Heatmaps สำหรับ traffic patterns
Histograms สำหรับการกระจาย

4. 5 หมวดหมู่การวิเคราะห์

📊 ภาพรวม: สถิติรวมและ trends หลัก
🌐 IP Analysis: วิเคราะห์ IP addresses
🔗 URL Analysis: วิเคราะห์ URLs และ file types
🔒 Security Analysis: ตรวจจับกิจกรรมน่าสงสัย
📈 Traffic Patterns: รูปแบบการใช้งาน

5. ฟีเจอร์เพิ่มเติม

การดาวน์โหลดข้อมูลที่ประมวลผลแล้ว
รายงานสรุปแบบ text
Real-time metrics
Security alerts

🚀 วิธีการติดตั้งและใช้งาน:
1. ติดตั้ง Dependencies:
bashpip install streamlit pandas matplotlib plotly seaborn numpy
2. บันทึกโค้ดเป็นไฟล์:
bash# บันทึกเป็น streamlit_log_analyzer.py
3. รันแอปพลิเคชัน:
bashstreamlit run streamlit_log_analyzer.py
4. เข้าใช้งานผ่าน Browser:
http://localhost:8501
📊 ฟีเจอร์การแสดงผล:

Real-time Metrics: แสดงจำนวน requests, IPs, URLs, error rate
Interactive Charts: สามารถ zoom, hover, filter ได้
Data Tables: แสดงข้อมูลรายละเอียดแบบตาราง
Security Alerts: การแจ้งเตือนเมื่อพบกิจกรรมน่าสงสัย
Export Functions: ดาวน์โหลดข้อมูลและรายงาน

🎯 การใช้งาน:

อัปโหลดไฟล์: ใช้ sidebar เพื่ือเลือกไฟล์ log
ดูข้อมูลภาพรวม: ตรวจสอบ metrics หลัก
วิเคราะห์แต่ละหมวด: ใช้ tabs เพื่อดูรายละเอียด
ตรวจสอบความปลอดภัย: ดู security alerts
ดาวน์โหลดผลลัพธ์: Export ข้อมูลและรายงาน

แอปพลิเคชันนี้จะทำให้การวิเคราะห์ log ไฟล์เป็นเรื่องง่ายและมีประสิทธิภาพมากขึ้น! 🎉
