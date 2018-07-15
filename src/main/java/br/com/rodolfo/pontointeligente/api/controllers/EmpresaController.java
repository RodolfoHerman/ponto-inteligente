package br.com.rodolfo.pontointeligente.api.controllers;

import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.rodolfo.pontointeligente.api.dtos.EmpresaDto;
import br.com.rodolfo.pontointeligente.api.entities.Empresa;
import br.com.rodolfo.pontointeligente.api.response.Response;
import br.com.rodolfo.pontointeligente.api.services.EmpresaService;

/**
 * EmpresaController
 */
@RestController
@RequestMapping("/api/empresas")
@CrossOrigin(origins = "*")
public class EmpresaController {

    private static final Logger log = LoggerFactory.getLogger(EmpresaController.class);

    @Autowired
    private EmpresaService empresaService;
    
    public EmpresaController() {}

    /**
     * Retorna uma empresa dado um CNPJ
     * 
     * @param cnpj
     * @return ResponseEntity<Response<EmpresaDto>>
     */
    @GetMapping(value = "/cnpj/{cnpj}")
    public ResponseEntity<Response<EmpresaDto>> buscarPorCnpj(@PathVariable("cnpj") String cnpj) {

        log.info("Buscando empresa por CNPJ: {}", cnpj);

        Response<EmpresaDto> response = new Response<>();

        Optional<Empresa> empresa = this.empresaService.BuscarPorCnpj(cnpj);

        if(!empresa.isPresent()) {

            log.info("Empresa não encontrada para o CNPJ: {}", cnpj);
            response.getErrors().add("Empresa não encontrada para o CNPJ: " + cnpj);
            return ResponseEntity.badRequest().body(response);
        }

        response.setData(this.converterEmpresaDto(empresa.get()));

        return ResponseEntity.ok(response);
    }

    /**
     * Populao DTO de cadastro com os dados da empresa
     * 
     * @param empresa
     * @return EmpresaDto
     */
	private EmpresaDto converterEmpresaDto(Empresa empresa) {
        
        EmpresaDto empresaDto = new EmpresaDto();
        
        empresaDto.setId(empresa.getId());
        empresaDto.setRazaoSocial(empresa.getRazaoSocial());
        empresaDto.setCnpj(empresa.getCnpj());
        
        return empresaDto;
	}



}