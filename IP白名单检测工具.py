import ipaddress
import os
import json
from datetime import datetime
import re

# 终端颜色设置
class Colors:
    RESET = '\033[0m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def parse_ip_range(ip_str):
    """解析各种格式的IP范围，返回规范化的IP列表或CIDR"""
    ip_str = ip_str.strip()
    
    # 处理CIDR格式（已规范化，直接返回）
    if '/' in ip_str:
        try:
            ipaddress.ip_network(ip_str, strict=False)
            return [ip_str]
        except ValueError:
            print(f"{Colors.RED}警告：无效的CIDR格式 - {ip_str}，已跳过{Colors.RESET}")
            return []
    
    # 处理单个IP（直接返回）
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_str):
        try:
            ipaddress.ip_address(ip_str)
            return [ip_str]
        except ValueError:
            print(f"{Colors.RED}警告：无效的IP地址 - {ip_str}，已跳过{Colors.RESET}")
            return []
    
    # 处理范围格式（支持-和～两种分隔符）
    range_match = re.match(r'^(.+?)(-|～)(.+)$', ip_str)
    if range_match:
        start_part = range_match.group(1).strip()
        end_part = range_match.group(3).strip()
        separator = range_match.group(2)
        
        # 情况1：完整IP范围（如192.168.1.1-192.168.1.10）
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', start_part) and \
           re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', end_part):
            try:
                start_ip = ipaddress.ip_address(start_part)
                end_ip = ipaddress.ip_address(end_part)
                if start_ip > end_ip:
                    start_ip, end_ip = end_ip, start_ip
                
                # 生成范围内所有IP
                ip_list = []
                current_ip = start_ip
                while current_ip <= end_ip:
                    ip_list.append(str(current_ip))
                    current_ip += 1
                return ip_list
            except ValueError:
                print(f"{Colors.RED}警告：无效的IP范围 - {ip_str}，已跳过{Colors.RESET}")
                return []
        
        # 情况2：简写范围（如192.168.1.1-10 或 211.95.80.2-5）
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', start_part) and \
           re.match(r'^\d{1,3}$', end_part):
            try:
                # 提取IP前缀
                prefix = ".".join(start_part.split('.')[:3])
                start_last = int(start_part.split('.')[3])
                end_last = int(end_part)
                
                if start_last > end_last:
                    start_last, end_last = end_last, start_last
                
                # 生成范围内所有IP
                ip_list = []
                for last in range(start_last, end_last + 1):
                    ip = f"{prefix}.{last}"
                    ipaddress.ip_address(ip)  # 验证IP有效性
                    ip_list.append(ip)
                return ip_list
            except ValueError:
                print(f"{Colors.RED}警告：无效的简写IP范围 - {ip_str}，已跳过{Colors.RESET}")
                return []
    
    # 无法识别的格式
    print(f"{Colors.RED}警告：无法识别的IP格式 - {ip_str}，已跳过{Colors.RESET}")
    return []

def is_ip_in_whitelist(ip, whitelist):
    """检查IP是否在白名单中"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for entry in whitelist:
            if '/' in entry:
                # 处理CIDR格式
                network = ipaddress.ip_network(entry, strict=False)
                if ip_obj in network:
                    return True
            else:
                # 处理单个IP
                if ip == entry:
                    return True
        return False
    except ValueError:
        print(f"{Colors.RED}错误：无效的IP地址格式 - {ip}{Colors.RESET}")
        return False

def process_ip_file(input_file_path, whitelist):
    """处理IP文件并输出不在白名单中的IP"""
    if not os.path.exists(input_file_path):
        print(f"{Colors.RED}错误：文件 '{input_file_path}' 不存在{Colors.RESET}")
        return False
    
    with open(input_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    # 读取所有IP并去重
    ips = set()
    for line in lines:
        ip = line.strip()
        if ip:  # 跳过空行
            ips.add(ip)
    
    if not ips:
        print(f"{Colors.RED}错误：输入文件中没有有效的IP地址{Colors.RESET}")
        return False
    
    # 检查每个IP
    non_whitelisted_ips = []
    for ip in ips:
        if not is_ip_in_whitelist(ip, whitelist):
            non_whitelisted_ips.append(ip)
    
    # 创建输出目录
    input_dir = os.path.dirname(os.path.abspath(input_file_path))
    output_dir = os.path.join(input_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    
    # 生成输出文件名
    base_name = os.path.splitext(os.path.basename(input_file_path))[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file_path = os.path.join(output_dir, f"{base_name}_non_whitelisted_{timestamp}.txt")
    
    # 输出结果
    if non_whitelisted_ips:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            for ip in non_whitelisted_ips:
                f.write(f"{ip}\n")
        
        # 打印不在范围内的IP
        print(f"\n{Colors.BLUE}不在白名单范围内的IP：{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.UNDERLINE}{'-' * 30}{Colors.RESET}")
        for ip in non_whitelisted_ips:
            print(ip)
        print(f"{Colors.BOLD}{Colors.UNDERLINE}{'-' * 30}{Colors.RESET}")
        
        print(f"{Colors.GREEN}已完成检查，发现 {len(non_whitelisted_ips)} 个不在白名单中的IP{Colors.RESET}")
        print(f"{Colors.CYAN}结果已保存到文件：{output_file_path}{Colors.RESET}")
    else:
        print(f"{Colors.GREEN}所有IP都在白名单范围内{Colors.RESET}")
    
    return True

def load_whitelist_from_file(file_path):
    """从文件加载白名单并自动处理各种格式"""
    try:
        if not os.path.exists(file_path):
            print(f"{Colors.YELLOW}警告：白名单文件 '{file_path}' 不存在，将使用空白名单{Colors.RESET}")
            return []
            
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
        
        # 解析每一行，处理各种格式
        whitelist = []
        for line in lines:
            parsed_ips = parse_ip_range(line)
            whitelist.extend(parsed_ips)
        
        # 去重处理
        whitelist = list(set(whitelist))
        print(f"{Colors.GREEN}成功加载白名单，共 {len(whitelist)} 个有效IP/网段{Colors.RESET}")
        return whitelist
        
    except Exception as e:
        print(f"{Colors.RED}错误：加载白名单文件时发生异常: {e}{Colors.RESET}")
        return []

def save_whitelist_to_file(whitelist, file_path):
    """保存白名单到文件（保留原始输入格式，只在加载时解析）"""
    try:
        # 保存时按原始格式（不转换），只在加载时解析
        with open(file_path, 'w', encoding='utf-8') as f:
            for entry in whitelist:
                f.write(f"{entry}\n")
        print(f"{Colors.GREEN}白名单已保存到 {file_path}{Colors.RESET}")
        return True
    except Exception as e:
        print(f"{Colors.RED}错误：保存白名单文件时发生异常: {e}{Colors.RESET}")
        return False

def manage_whitelist(whitelist_file):
    """管理白名单界面"""
    whitelist = load_whitelist_from_file(whitelist_file)
    
    while True:
        print(f"\n{Colors.BLUE}白名单管理{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.UNDERLINE}{'-' * 20}{Colors.RESET}")
        print(f"当前白名单条目数: {len(whitelist)}")
        print("1. 查看白名单")
        print("2. 添加IP/网段")
        print("3. 删除IP/网段")
        print("4. 保存白名单")
        print("5. 刷新白名单（从文件重新加载）")
        print("b. 返回主菜单")
        
        choice = input("请输入选项：").strip().lower()
        
        if choice == '1':
            print(f"\n{Colors.CYAN}当前白名单内容:{Colors.RESET}")
            for i, entry in enumerate(whitelist, 1):
                print(f"{i}. {entry}")
                
        elif choice == '2':
            entry = input("请输入要添加的IP或网段（支持各种格式）：").strip()
            if not entry:
                print(f"{Colors.RED}错误：输入不能为空{Colors.RESET}")
                continue
                
            # 解析输入的IP范围
            parsed_ips = parse_ip_range(entry)
            if not parsed_ips:
                print(f"{Colors.RED}错误：无法解析输入的IP范围{Colors.RESET}")
                continue
                
            # 添加到白名单（去重）
            added_count = 0
            for ip in parsed_ips:
                if ip not in whitelist:
                    whitelist.append(ip)
                    added_count += 1
                    
            print(f"{Colors.GREEN}成功添加 {added_count} 个IP/网段{Colors.RESET}")
                
        elif choice == '3':
            entry = input("请输入要删除的IP或网段：").strip()
            if not entry:
                print(f"{Colors.RED}错误：输入不能为空{Colors.RESET}")
                continue
                
            # 解析输入的IP范围
            parsed_ips = parse_ip_range(entry)
            if not parsed_ips:
                print(f"{Colors.RED}错误：无法解析输入的IP范围{Colors.RESET}")
                continue
                
            # 从白名单中删除
            removed_count = 0
            for ip in parsed_ips:
                if ip in whitelist:
                    whitelist.remove(ip)
                    removed_count += 1
                    
            if removed_count > 0:
                print(f"{Colors.GREEN}成功删除 {removed_count} 个IP/网段{Colors.RESET}")
            else:
                print(f"{Colors.RED}未找到匹配的IP/网段{Colors.RESET}")
                
        elif choice == '4':
            if save_whitelist_to_file(whitelist, whitelist_file):
                print(f"{Colors.GREEN}白名单已成功保存{Colors.RESET}")
                
        elif choice == '5':
            print(f"{Colors.YELLOW}正在从文件重新加载白名单...{Colors.RESET}")
            whitelist = load_whitelist_from_file(whitelist_file)
            print(f"{Colors.GREEN}白名单已刷新{Colors.RESET}")
                
        elif choice == 'b':
            break
            
        else:
            print(f"{Colors.RED}无效的选项，请重新输入{Colors.RESET}")
    
    return whitelist

def single_ip_check_mode(whitelist):
    """单个IP检查模式（循环检查直到用户选择返回）"""
    while True:
        ip_input = input("\n请输入需要查询的IP地址（输入'b'返回主菜单）：").strip()
        
        if ip_input.lower() == 'b':
            break
            
        if not ip_input:
            print(f"{Colors.RED}错误：IP地址不能为空{Colors.RESET}")
            continue
            
        if is_ip_in_whitelist(ip_input, whitelist):
            print(f"{Colors.GREEN}IP {ip_input} 在白名单范围内{Colors.RESET}")
        else:
            print(f"{Colors.RED}IP {ip_input} 不在白名单范围内{Colors.RESET}")

def main():
    WHITELIST_FILE = "whitelist.txt"  # 白名单文件路径
    
    # 精准匹配 WhiteIPSearch 的 ASCII 艺术启动界面
    print(r"""
 ___       __   ___  ___  ___  _________  _______   ___  ________   
|\  \     |\  \|\  \|\  \|\  \|\___   ___|\  ___ \ |\  \|\   __  \  
\ \  \    \ \  \ \  \\\  \ \  \|___ \  \_\ \   __/|\ \  \ \  \|\  \ 
 \ \  \  __\ \  \ \   __  \ \  \   \ \  \ \ \  \_|/_\ \  \ \   ____\
  \ \  \|\__\_\  \ \  \ \  \ \  \   \ \  \ \ \  \_|\ \ \  \ \  \___|
   \ \____________\ \__\ \__\ \__\   \ \__\ \ \_______\ \__\ \__\   
    \|____________|\|__|\|__|\|__|    \|__|  \|_______|\|__|\|__|   
                                                 
                     https://github.com/tzyyyyyyy/WhiteIPSearch  By:tzyyy  
    """)


    
    # 加载白名单
    whitelist = load_whitelist_from_file(WHITELIST_FILE)
    
    while True:
        print("\n请选择操作模式：")
        print("1. 单个IP检查")
        print("2. 批量文件检查")
        print("3. 白名单管理")
        print("q. 退出程序")
        
        choice = input("请输入选项：").strip().lower()
        
        if choice == '1':
            single_ip_check_mode(whitelist)
        elif choice == '2':
            input_file = input("请输入包含IP列表的文件路径：").strip()
            if not input_file:
                print(f"{Colors.RED}错误：输入文件路径不能为空{Colors.RESET}")
                continue
            process_ip_file(input_file, whitelist)
        elif choice == '3':
            whitelist = manage_whitelist(WHITELIST_FILE)
        elif choice == 'q':
            print(f"{Colors.GREEN}感谢使用，再见！{Colors.RESET}")
            break
        else:
            print(f"{Colors.RED}无效的选项，请重新输入{Colors.RESET}")

if __name__ == "__main__":
    main()
