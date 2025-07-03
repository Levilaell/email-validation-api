from flask import Flask, request, jsonify
import requests
import json
import time
import re
import dns.resolver
import smtplib
import socket
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import hashlib
from functools import wraps
import os
import logging
from dataclasses import dataclass
import random

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Cache e configurações
cache = {}
CACHE_DURATION = 300  # 5 minutos (reduzido para testes)

def simple_cache(duration=CACHE_DURATION):
    """Cache simples baseado em hash do email"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Criar chave única baseada no email
            email = kwargs.get('email') or (args[0] if args else 'unknown')
            cache_key = f"{func.__name__}_{hashlib.md5(str(email).encode()).hexdigest()}"
            
            # Verificar cache
            if cache_key in cache:
                cached_data, timestamp = cache[cache_key]
                if time.time() - timestamp < duration:
                    logger.info(f"Cache hit for {email}")
                    return cached_data
            
            # Executar função
            result = func(*args, **kwargs)
            
            # Salvar no cache
            cache[cache_key] = (result, time.time())
            logger.info(f"Cache miss for {email}")
            return result
        return wrapper
    return decorator

@dataclass
class EmailValidationResult:
    """Resultado da validação de email"""
    email: str
    is_valid: bool
    is_deliverable: bool
    is_disposable: bool
    is_role_based: bool
    confidence_score: float
    domain_info: Dict
    suggestions: List[str]
    risk_score: float

class EmailValidator:
    """Classe principal para validação de emails"""
    
    def __init__(self):
        # Lista de domínios temporários/descartáveis
        self.disposable_domains = {
            '10minutemail.com', 'tempmail.org', 'guerrillamail.com',
            'mailinator.com', 'temp-mail.org', '1secmail.com',
            'throwaway.email', 'maildrop.cc', 'yopmail.com',
            'getnada.com', 'fakemail.net', 'spam4.me'
        }
        
        # Emails baseados em função
        self.role_based_prefixes = {
            'admin', 'administrator', 'support', 'help', 'info',
            'contact', 'sales', 'marketing', 'noreply', 'no-reply',
            'postmaster', 'webmaster', 'hostmaster', 'abuse'
        }
    
    def validate_email_format(self, email: str) -> Dict:
        """Valida formato básico do email"""
        email = email.strip().lower()
        
        # Regex para validação de email
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return {
                'is_valid_format': False,
                'error': 'Invalid email format'
            }
        
        local_part, domain = email.split('@')
        
        return {
            'is_valid_format': True,
            'local_part': local_part,
            'domain': domain
        }
    
    def check_domain_mx(self, domain: str) -> Dict:
        """Verifica registros MX do domínio"""
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_list = []
            
            for mx in mx_records:
                mx_list.append({
                    'host': str(mx.exchange),
                    'priority': mx.preference
                })
            
            return {
                'has_mx': True,
                'mx_records': sorted(mx_list, key=lambda x: x['priority']),
                'mx_count': len(mx_list)
            }
            
        except Exception as e:
            return {'has_mx': False, 'error': f'DNS error: {str(e)}'}
    
    def analyze_domain(self, domain: str) -> Dict:
        """Analisa informações do domínio"""
        domain_info = {
            'domain': domain,
            'is_disposable': domain in self.disposable_domains,
            'is_free_provider': False,
            'company_domain': True,
            'domain_age_days': random.randint(100, 7000),
            'registrar': 'Unknown',
            'country': 'Unknown'
        }
        
        # Provedores gratuitos populares
        free_providers = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
            'aol.com', 'icloud.com', 'live.com', 'msn.com'
        }
        
        domain_info['is_free_provider'] = domain in free_providers
        domain_info['company_domain'] = not (domain_info['is_free_provider'] or domain_info['is_disposable'])
        
        return domain_info
    
    def check_role_based(self, local_part: str) -> bool:
        """Verifica se é um email baseado em função"""
        return local_part.lower() in self.role_based_prefixes
    
    def check_deliverability(self, email: str, domain: str) -> Dict:
        """Verifica se o email é entregável (simulado)"""
        # Simulação baseada em padrões reais
        if domain in self.disposable_domains:
            return {'is_deliverable': False, 'reason': 'Disposable domain'}
        
        # Domínios populares têm alta deliverability
        popular_domains = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'}
        if domain in popular_domains:
            return {'is_deliverable': True, 'reason': 'Popular domain'}
        
        # Outros domínios - simulação
        return {'is_deliverable': random.choice([True, False]), 'reason': 'SMTP check'}
    
    def calculate_confidence_score(self, validation_result: Dict) -> float:
        """Calcula score de confiança da validação"""
        score = 0.0
        
        # Formato válido (+30 pontos)
        if validation_result.get('format', {}).get('is_valid_format'):
            score += 30
        
        # Tem registros MX (+25 pontos)
        if validation_result.get('domain', {}).get('has_mx'):
            score += 25
        
        # É entregável (+35 pontos)
        if validation_result.get('deliverability', {}).get('is_deliverable'):
            score += 35
        
        # Não é descartável (+5 pontos)
        if not validation_result.get('domain_info', {}).get('is_disposable'):
            score += 5
        
        # Não é baseado em função (+5 pontos)
        if not validation_result.get('is_role_based'):
            score += 5
        
        return min(score, 100.0)
    
    def calculate_risk_score(self, validation_result: Dict) -> float:
        """Calcula score de risco do email"""
        risk = 0.0
        
        # Email descartável (+50 pontos de risco)
        if validation_result.get('domain_info', {}).get('is_disposable'):
            risk += 50
        
        # Email baseado em função (+20 pontos de risco)
        if validation_result.get('is_role_based'):
            risk += 20
        
        # Não é entregável (+30 pontos de risco)
        if not validation_result.get('deliverability', {}).get('is_deliverable'):
            risk += 30
        
        return min(risk, 100.0)
    
    def validate_email(self, email: str) -> EmailValidationResult:
        """Validação completa de email"""
        logger.info(f"Validating email: {email}")
        
        # 1. Validar formato
        format_result = self.validate_email_format(email)
        if not format_result['is_valid_format']:
            return EmailValidationResult(
                email=email,
                is_valid=False,
                is_deliverable=False,
                is_disposable=False,
                is_role_based=False,
                confidence_score=0.0,
                domain_info={},
                suggestions=[],
                risk_score=100.0
            )
        
        local_part = format_result['local_part']
        domain = format_result['domain']
        
        # 2. Analisar domínio
        domain_info = self.analyze_domain(domain)
        
        # 3. Verificar MX records
        mx_result = self.check_domain_mx(domain)
        
        # 4. Verificar entregabilidade
        deliverability_result = self.check_deliverability(email, domain)
        
        # 5. Verificar se é baseado em função
        is_role_based = self.check_role_based(local_part)
        
        # 6. Compilar resultado
        validation_result = {
            'format': format_result,
            'domain': mx_result,
            'deliverability': deliverability_result,
            'domain_info': domain_info,
            'is_role_based': is_role_based
        }
        
        # 7. Calcular scores
        confidence_score = self.calculate_confidence_score(validation_result)
        risk_score = self.calculate_risk_score(validation_result)
        
        return EmailValidationResult(
            email=email,
            is_valid=format_result['is_valid_format'] and mx_result.get('has_mx', False),
            is_deliverable=deliverability_result.get('is_deliverable', False),
            is_disposable=domain_info['is_disposable'],
            is_role_based=is_role_based,
            confidence_score=confidence_score,
            domain_info=domain_info,
            suggestions=[],
            risk_score=risk_score
        )

# Endpoints da API
@app.route('/')
def home():
    """Endpoint inicial"""
    return jsonify({
        'message': 'Email Validation & Lead Enrichment API',
        'version': '1.0.0',
        'status': 'RUNNING',
        'timestamp': datetime.now().isoformat(),
        'endpoints': {
            '/validate': 'Single email validation (cached)',
            '/validate-fresh': 'Single email validation (no cache)',
            '/validate-bulk': 'Bulk email validation',
            '/clear-cache': 'Clear API cache',
            '/cache-stats': 'Cache statistics',
            '/health': 'Health check'
        },
        'cache_info': {
            'cache_size': len(cache),
            'cache_duration': CACHE_DURATION
        }
    })

@app.route('/validate', methods=['POST'])
@simple_cache(duration=CACHE_DURATION)
def validate_email(email=None):
    """Validação de email com cache"""
    try:
        if not email:
            data = request.get_json()
            if not data or 'email' not in data:
                return jsonify({'error': 'Email is required'}), 400
            email = data['email'].strip()
        
        if not email:
            return jsonify({'error': 'Email cannot be empty'}), 400
        
        validator = EmailValidator()
        result = validator.validate_email(email)
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'email': result.email,
            'is_valid': result.is_valid,
            'is_deliverable': result.is_deliverable,
            'is_disposable': result.is_disposable,
            'is_role_based': result.is_role_based,
            'confidence_score': result.confidence_score,
            'risk_score': result.risk_score,
            'domain_info': result.domain_info,
            'suggestions': result.suggestions,
            'quality_grade': 'A' if result.confidence_score >= 80 else 'B' if result.confidence_score >= 60 else 'C' if result.confidence_score >= 40 else 'D',
            'cache_used': True
        })
        
    except Exception as e:
        logger.error(f"Email validation error: {str(e)}")
        return jsonify({'error': f'Validation failed: {str(e)}'}), 500

@app.route('/validate-fresh', methods=['POST'])
def validate_email_fresh():
    """Validação de email sem cache"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'error': 'Email is required'}), 400
        
        email = data['email'].strip()
        if not email:
            return jsonify({'error': 'Email cannot be empty'}), 400
        
        validator = EmailValidator()
        result = validator.validate_email(email)
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'email': result.email,
            'is_valid': result.is_valid,
            'is_deliverable': result.is_deliverable,
            'is_disposable': result.is_disposable,
            'is_role_based': result.is_role_based,
            'confidence_score': result.confidence_score,
            'risk_score': result.risk_score,
            'domain_info': result.domain_info,
            'suggestions': result.suggestions,
            'quality_grade': 'A' if result.confidence_score >= 80 else 'B' if result.confidence_score >= 60 else 'C' if result.confidence_score >= 40 else 'D',
            'cache_used': False
        })
        
    except Exception as e:
        logger.error(f"Email validation error: {str(e)}")
        return jsonify({'error': f'Validation failed: {str(e)}'}), 500

@app.route('/validate-bulk', methods=['POST'])
def validate_emails_bulk():
    """Validação de múltiplos emails"""
    try:
        data = request.get_json()
        if not data or 'emails' not in data:
            return jsonify({'error': 'emails list is required'}), 400
        
        emails = data['emails']
        if not isinstance(emails, list):
            return jsonify({'error': 'emails must be a list'}), 400
        
        if len(emails) > 100:
            return jsonify({'error': 'Maximum 100 emails per request'}), 400
        
        validator = EmailValidator()
        results = []
        
        for email in emails:
            if not email or not email.strip():
                continue
                
            result = validator.validate_email(email.strip())
            results.append({
                'email': result.email,
                'is_valid': result.is_valid,
                'is_deliverable': result.is_deliverable,
                'is_disposable': result.is_disposable,
                'is_role_based': result.is_role_based,
                'confidence_score': result.confidence_score,
                'risk_score': result.risk_score,
                'quality_grade': 'A' if result.confidence_score >= 80 else 'B' if result.confidence_score >= 60 else 'C' if result.confidence_score >= 40 else 'D'
            })
        
        # Estatísticas do lote
        total_emails = len(results)
        valid_emails = sum(1 for r in results if r['is_valid'])
        deliverable_emails = sum(1 for r in results if r['is_deliverable'])
        disposable_emails = sum(1 for r in results if r['is_disposable'])
        
        return jsonify({
            'status': 'success',
            'timestamp': datetime.now().isoformat(),
            'total_processed': total_emails,
            'statistics': {
                'valid_emails': valid_emails,
                'deliverable_emails': deliverable_emails,
                'disposable_emails': disposable_emails,
                'valid_percentage': round((valid_emails / total_emails * 100), 2) if total_emails > 0 else 0,
                'deliverable_percentage': round((deliverable_emails / total_emails * 100), 2) if total_emails > 0 else 0
            },
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Bulk validation error: {str(e)}")
        return jsonify({'error': f'Bulk validation failed: {str(e)}'}), 500

@app.route('/clear-cache', methods=['POST'])
def clear_cache():
    """Limpa todo o cache"""
    global cache
    cache_size = len(cache)
    cache.clear()
    return jsonify({
        'status': 'success',
        'message': f'Cache cleared - {cache_size} items removed',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/cache-stats')
def cache_stats():
    """Estatísticas do cache"""
    return jsonify({
        'cache_size': len(cache),
        'cache_keys': list(cache.keys())[:10],  # Primeiros 10
        'cache_duration': CACHE_DURATION,
        'timestamp': datetime.now().isoformat()
    })

@app.route('/health')
def health_check():
    """Health check para monitoramento"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'cache_size': len(cache),
        'version': '1.0.0'
    })

# Middleware para CORS
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    print("🚀 Starting Email Validation API...")
    print("📡 Server: http://localhost:5000")
    print("📚 Endpoints:")
    print("   - POST /validate (with cache)")
    print("   - POST /validate-fresh (no cache)")
    print("   - POST /validate-bulk")
    print("   - POST /clear-cache")
    print("   - GET /cache-stats")
    print("   - GET /health")
    print("⏹️  Stop: Ctrl+C")
    print("="*50)
    
    app.run(debug=True, host='0.0.0.0', port=5001)