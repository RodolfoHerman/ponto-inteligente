package br.com.rodolfo.pontointeligente.api.services.impl;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import br.com.rodolfo.pontointeligente.api.entities.Lancamento;
import br.com.rodolfo.pontointeligente.api.repositories.LancamentoRepository;
import br.com.rodolfo.pontointeligente.api.services.LancamentoService;

/**
 * LancamentoServiceImpl
 */
@Service
public class LancamentoServiceImpl implements LancamentoService {

    private static final Logger log = LoggerFactory.getLogger(LancamentoServiceImpl.class);

    @Autowired
    private LancamentoRepository lancamentoRepository;

	@Override
	public Page<Lancamento> buscarFuncionarioPorId(Long funcionarioId, PageRequest pageRequest) {
        
        log.info("Buscando lançamentos para o funcionário ID: {}", funcionarioId);
        
        return lancamentoRepository.findByFuncionarioId(funcionarioId,pageRequest);
	}

	@Override
	public Optional<Lancamento> buscarPorId(Long id) {
        
        log.info("Buscando um lançamento pelo ID: {}", id);
        
        return lancamentoRepository.findById(id);
	}

	@Override
	public Lancamento persistir(Lancamento lancamento) {
        
        log.info("Persistindo o lançamento: {}", lancamento);
        
        return lancamentoRepository.save(lancamento);
	}

	@Override
	public void remover(Long id) {
        
        log.info("Removendo o lançamento de ID: {}", id);

        lancamentoRepository.deleteById(id);
	}

    
}